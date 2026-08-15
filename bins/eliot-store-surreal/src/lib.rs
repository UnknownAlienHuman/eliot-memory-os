#![forbid(unsafe_code)]

//! Composition owner for the S-03 canonical store bridge.
//!
//! This process exposes only the store-neutral EBP contract.  SurrealDB
//! credentials, provider transport and query text stay inside
//! `eliot-store-surreal-adapter`; this root only assembles the adapter and
//! serializes bounded contract receipts. Blob contributes one process/root
//! claim identity; it is not a second store or semantic write path.

use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_blob::BlobRootOwner;
use eliot_platform::ClockObservation;
use eliot_store_api::{
    CanonicalStoreClient, NamedReadRequest, NamedReadResponse, OperationId,
    OrderingHeadExpectation, PreparedTransition, RequestMeta, RevisionHeadExpectation,
    WriteReceipt,
};
use eliot_store_surreal_adapter::{
    AdapterError, AdapterHealth, MigrationReceipt, PINNED_SURREALDB_MAJOR, SchemaGeneration,
    SemanticReadiness, SurrealAdapterConfig, SurrealStoreAdapter,
};
use eliot_types::{CredentialProviderKind, GovernorConfig};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

pub const SERVICE_NAME: &str = "eliot-store-surreal";
pub const PROTOCOL_VERSION: &str = "eliot.s03.ebp.v1";
const SCHEMA_GENERATION: &str = "1.0.0";

/// Canonical store composition. All provider authority is held by the one
/// adapter and one process/root Blob claim; Blob does not become a semantic
/// store or alternate transition path.
pub struct StoreComposition {
    store: SurrealStoreAdapter,
    blob: BlobRootOwner,
}

impl std::fmt::Debug for StoreComposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreComposition")
            .field("store", &self.store)
            .field("blob_owner", &self.blob)
            .finish()
    }
}

impl StoreComposition {
    /// Builds the adapter from the existing process configuration. The
    /// configured provider is the only credential authority; this process
    /// never accepts an ambient password environment variable or an empty
    /// fallback.
    pub fn new(config: GovernorConfig) -> Result<Self, String> {
        config.validate().map_err(|error| error.to_string())?;
        let store = SurrealStoreAdapter::new(adapter_config(&config)?);
        let blob = BlobRootOwner::claim(
            config.blob_store.root.clone(),
            format!("store-composition:{}", config.service.instance_id),
            std::process::id(),
        )
        .map_err(|error| format!("claim Blob root owner: {error}"))?;
        Ok(Self { store, blob })
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
    Ok(SurrealAdapterConfig {
        endpoint: config.db.surreal.endpoint.clone(),
        namespace: config.db.surreal.ns.clone(),
        database: config.db.surreal.db.clone(),
        username: config.db.surreal.user.clone(),
        password: resolve_surreal_password(config)?,
        connect_timeout_ms: config.db.surreal.startup_timeout_ms,
        query_timeout_ms: config.db.surreal.query_timeout_ms,
        expected_provider_major: PINNED_SURREALDB_MAJOR,
        expected_schema_generation: schema_generation,
    })
}

fn resolve_surreal_password(config: &GovernorConfig) -> Result<SecretString, String> {
    let surreal = &config.db.surreal;
    match surreal.credential_provider {
        CredentialProviderKind::WindowsCredentialManager => {
            let bytes = eliot_windows_ipc::credential_read_current_user(&surreal.credential_id)
                .map_err(|error| format!("read configured Windows credential: {error}"))?
                .ok_or_else(|| {
                    format!(
                        "configured Windows credential is missing: {}",
                        surreal.credential_id
                    )
                })?;
            let password = String::from_utf8(bytes)
                .map_err(|_| "configured Windows credential is not UTF-8".to_owned())?;
            non_empty_secret(password, "configured Windows credential")
        }
        CredentialProviderKind::LegacyPasswordFile => {
            if std::env::var("ELIOT_ALLOW_LEGACY_PASSWORD_FILE_MIGRATION").as_deref() != Ok("1") {
                return Err(
                    "legacy SurrealDB password_file requires the explicit migration gate"
                        .to_owned(),
                );
            }
            let path = resolve_password_path(&surreal.password_file)?;
            let password = std::fs::read_to_string(&path).map_err(|error| {
                format!(
                    "read configured SurrealDB password file {}: {error}",
                    path.display()
                )
            })?;
            non_empty_secret(password, "configured SurrealDB password file")
        }
        provider => Err(format!(
            "unsupported configured SurrealDB credential provider: {provider:?}"
        )),
    }
}

fn non_empty_secret(value: String, source: &str) -> Result<SecretString, String> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(format!("{source} is empty"));
    }
    Ok(SecretString::new(value.into()))
}

fn resolve_password_path(configured: &str) -> Result<PathBuf, String> {
    let prefix = ["%LOCALAPPDATA%/", "%LOCALAPPDATA%\\"]
        .into_iter()
        .find(|prefix| {
            configured
                .get(..prefix.len())
                .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
        })
        .ok_or_else(|| "db.surreal.password_file must use the %LOCALAPPDATA%/ prefix".to_owned())?;
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| "LOCALAPPDATA is required by db.surreal.password_file".to_owned())?;
    let local_app_data = PathBuf::from(local_app_data);
    if !local_app_data.is_absolute() {
        return Err("LOCALAPPDATA must be absolute for db.surreal.password_file".to_owned());
    }
    let relative = &configured[prefix.len()..];
    let relative_path = Path::new(relative);
    if relative.is_empty()
        || configured.ends_with(['/', '\\'])
        || !relative_path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        || relative_path.file_name().is_none()
    {
        return Err(
            "db.surreal.password_file must be a normalized file below LOCALAPPDATA".to_owned(),
        );
    }
    Ok(local_app_data.join(relative_path))
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
/// from the configured SecretRef/provider only inside [`StoreComposition::new`].
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
    Health { record: AdapterHealth },
    Readiness { receipt: ReadinessReceipt },
    Migrated { receipt: MigrationResponse },
    Named { response: NamedReadResponse },
    Transaction { receipt: WriteReceipt },
    Receipt { receipt: Option<WriteReceipt> },
    Stopped,
    Error { error: String },
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
