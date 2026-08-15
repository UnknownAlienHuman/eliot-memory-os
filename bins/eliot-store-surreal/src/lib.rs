#![forbid(unsafe_code)]

//! Composition owner for the S-03 canonical store bridge.
//!
//! This process exposes only the store-neutral EBP contract.  SurrealDB
//! credentials, provider transport and query text stay inside
//! `eliot-store-surreal-adapter`; this root only assembles the adapter and
//! serializes bounded contract receipts. Blob contributes one process/root
//! claim identity; it is not a second store or semantic write path.

use std::path::Path;

use eliot_blob::BlobRootOwner;
use eliot_platform_windows::{NamedPipePeerExpectation, WindowsPlatform, read_protected_file};
use eliot_store_api::{
    CanonicalStoreClient, NamedReadRequest, NamedReadResponse, OperationId, OrderingHead,
    OrderingHeadExpectation, OrderingScopeId, PreparedTransition, RequestMeta, RevisionHead,
    RevisionHeadExpectation, RevisionKey, StoreError, StoreHealth, WriteReceipt,
};
pub use eliot_store_api::{ReadinessReceipt, StoreRequest as Request, StoreResponse as Response};
use eliot_store_surreal_adapter::{
    AdapterError, PINNED_SURREALDB_MAJOR, SchemaGeneration, SemanticReadiness,
    SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const SERVICE_NAME: &str = "eliot-store-surreal";
pub const PROTOCOL_VERSION: &str = "eliot.s03.ebp.v1";
const MAX_LAUNCH_CONFIG_BYTES: u64 = 256 * 1024;

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

/// Explicit, target-only process launch configuration.
///
/// This is intentionally not the legacy governor configuration.  The process
/// accepts only the connection coordinates, bounded timeouts, schema
/// generation, one Blob root, one process identity, and an opaque credential
/// reference.  Credential bytes are resolved after validation and never cross
/// this type or the EBP wire surface.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreLaunchConfig {
    pub store_pipe: String,
    /// Host-issued nonce for this exact Store process lineage.
    pub launch_nonce: String,
    /// SID/session the Store pipe must authenticate as its Kernel client.
    pub expected_client_sid: String,
    pub expected_client_session_id: u32,
    pub approved_artifact_hash: String,
    pub approved_config_hash: String,
    pub store_generation: u64,
    pub authority_epoch: u64,
    pub endpoint: String,
    pub namespace: String,
    pub database: String,
    pub username: String,
    pub connect_timeout_ms: u64,
    pub query_timeout_ms: u64,
    pub schema_generation: String,
    pub blob_root: String,
    pub instance_id: String,
    pub credential_ref: String,
}

impl StoreLaunchConfig {
    /// Validates every process-owned launch field before opening a provider or
    /// claiming the Blob root. No defaults are admitted.
    pub fn validate(&self) -> Result<(), String> {
        validate_launch_text(&self.store_pipe, "store_pipe")?;
        validate_launch_text(&self.launch_nonce, "launch_nonce")?;
        eliot_ipc::validate_pipe_name(&self.store_pipe)
            .map_err(|error| format!("invalid store_pipe: {error}"))?;
        NamedPipePeerExpectation::new(
            self.expected_client_sid.clone(),
            self.expected_client_session_id,
        )
        .map_err(|error| format!("invalid expected peer: {error}"))?;
        validate_digest(&self.approved_artifact_hash, "approved_artifact_hash")?;
        validate_digest(&self.approved_config_hash, "approved_config_hash")?;
        if self.approved_config_hash != launch_config_digest(self)? {
            return Err(
                "approved_config_hash does not bind the operational launch configuration"
                    .to_owned(),
            );
        }
        if self.store_generation == 0 || self.authority_epoch == 0 {
            return Err("store_generation and authority_epoch must be non-zero".to_owned());
        }
        validate_launch_text(&self.endpoint, "endpoint")?;
        if !self.endpoint.starts_with("ws://") && !self.endpoint.starts_with("wss://") {
            return Err("endpoint must start with ws:// or wss://".to_owned());
        }
        validate_launch_text(&self.namespace, "namespace")?;
        validate_launch_text(&self.database, "database")?;
        validate_launch_text(&self.username, "username")?;
        validate_launch_text(&self.schema_generation, "schema_generation")?;
        validate_launch_text(&self.blob_root, "blob_root")?;
        validate_launch_text(&self.instance_id, "instance_id")?;
        validate_launch_text(&self.credential_ref, "credential_ref")?;
        if self.connect_timeout_ms == 0 || self.query_timeout_ms == 0 {
            return Err("connect_timeout_ms and query_timeout_ms must be non-zero".to_owned());
        }
        SchemaGeneration::new(self.schema_generation.as_str())
            .map_err(|error| format!("invalid schema_generation: {error}"))?;
        if !Path::new(&self.blob_root).is_absolute() {
            return Err("blob_root must be an absolute path".to_owned());
        }
        Ok(())
    }
}

/// Computes the Host-approved digest over every operational launch field.
/// The digest field itself is deliberately excluded to prevent self-reference.
pub fn launch_config_digest(config: &StoreLaunchConfig) -> Result<String, String> {
    #[derive(Serialize)]
    struct OperationalConfig<'a> {
        store_pipe: &'a str,
        launch_nonce: &'a str,
        expected_client_sid: &'a str,
        expected_client_session_id: u32,
        approved_artifact_hash: &'a str,
        store_generation: u64,
        authority_epoch: u64,
        endpoint: &'a str,
        namespace: &'a str,
        database: &'a str,
        username: &'a str,
        connect_timeout_ms: u64,
        query_timeout_ms: u64,
        schema_generation: &'a str,
        blob_root: &'a str,
        instance_id: &'a str,
        credential_ref: &'a str,
    }
    let input = OperationalConfig {
        store_pipe: &config.store_pipe,
        launch_nonce: &config.launch_nonce,
        expected_client_sid: &config.expected_client_sid,
        expected_client_session_id: config.expected_client_session_id,
        approved_artifact_hash: &config.approved_artifact_hash,
        store_generation: config.store_generation,
        authority_epoch: config.authority_epoch,
        endpoint: &config.endpoint,
        namespace: &config.namespace,
        database: &config.database,
        username: &config.username,
        connect_timeout_ms: config.connect_timeout_ms,
        query_timeout_ms: config.query_timeout_ms,
        schema_generation: &config.schema_generation,
        blob_root: &config.blob_root,
        instance_id: &config.instance_id,
        credential_ref: &config.credential_ref,
    };
    let bytes =
        serde_json::to_vec(&input).map_err(|error| format!("serialize launch digest: {error}"))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn validate_digest(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("{field} must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn validate_launch_text(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(format!(
            "{field} must be non-blank and contain no control characters"
        ));
    }
    Ok(())
}

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
    /// Builds the adapter from the explicit target launch configuration.
    /// Credential bytes are read only inside this process from the configured
    /// Windows Credential Manager reference and are retained only by the
    /// adapter's redacted SecretString configuration.
    pub fn new(config: StoreLaunchConfig) -> Result<Self, String> {
        config.validate()?;
        let blob = BlobRootOwner::claim(
            config.blob_root.clone(),
            format!("store-composition:{}", config.instance_id),
            std::process::id(),
        )
        .map_err(|error| format!("claim Blob root owner: {error}"))?;
        let platform = WindowsPlatform::new(config.blob_root.clone())
            .map_err(|error| format!("validate Blob root for credential access: {error}"))?;
        let password = resolve_credential(&platform, &config.credential_ref)?;
        let store = SurrealStoreAdapter::new(adapter_config(&config, password)?);
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
    pub async fn health(&self) -> Result<StoreHealth, StoreError> {
        self.store.health().await
    }

    /// Semantic schema readiness observation.  This is not a write authority
    /// verdict and is returned as its own receipt/status surface.
    pub async fn readiness(&self) -> Result<ReadinessReceipt, StoreError> {
        let readiness = self
            .store
            .probe_readiness()
            .await
            .map_err(AdapterError::into_store_error)?;
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

fn adapter_config(
    config: &StoreLaunchConfig,
    password: SecretString,
) -> Result<SurrealAdapterConfig, String> {
    let schema_generation = SchemaGeneration::new(config.schema_generation.as_str())
        .map_err(|error| error.to_string())?;
    Ok(SurrealAdapterConfig {
        endpoint: config.endpoint.clone(),
        namespace: config.namespace.clone(),
        database: config.database.clone(),
        username: config.username.clone(),
        password,
        connect_timeout_ms: config.connect_timeout_ms,
        query_timeout_ms: config.query_timeout_ms,
        expected_provider_major: PINNED_SURREALDB_MAJOR,
        expected_schema_generation: schema_generation,
    })
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
    non_empty_secret(password, "configured credential")
}

fn non_empty_secret(value: String, source: &str) -> Result<SecretString, String> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(format!("{source} is empty"));
    }
    Ok(SecretString::new(value.into()))
}

/// Loads the process's explicit non-secret launch configuration from the
/// protected ProgramData contour. Secret material is resolved from the opaque
/// credential reference only inside `StoreComposition::new`. Missing or
/// out-of-contour configuration is an error; there is no default or legacy
/// configuration conversion.
pub fn load_config(path: Option<&Path>) -> Result<StoreLaunchConfig, String> {
    let Some(path) = path else {
        return Err("--config is required; launch config must be explicit".to_owned());
    };
    let bytes = read_protected_file(path, MAX_LAUNCH_CONFIG_BYTES)
        .map_err(|error| format!("read protected config: {error}"))?;
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => {
            let config: StoreLaunchConfig = serde_json::from_slice(&bytes)
                .map_err(|error| format!("parse JSON config: {error}"))?;
            config.validate()?;
            Ok(config)
        }
        Some("toml") => {
            let config: StoreLaunchConfig =
                toml::from_slice(&bytes).map_err(|error| format!("parse TOML config: {error}"))?;
            config.validate()?;
            Ok(config)
        }
        Some(extension) => Err(format!(
            "config extension must be .json or .toml, got .{extension}"
        )),
        None => Err("config path must have a .json or .toml extension".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> StoreLaunchConfig {
        let mut config = StoreLaunchConfig {
            store_pipe: r"\\.\pipe\eliot\store-test".to_owned(),
            launch_nonce: "launch-test".to_owned(),
            expected_client_sid: "S-1-5-18".to_owned(),
            expected_client_session_id: 0,
            approved_artifact_hash: "a".repeat(64),
            approved_config_hash: String::new(),
            store_generation: 1,
            authority_epoch: 1,
            endpoint: "ws://127.0.0.1:8000".to_owned(),
            namespace: "eliot".to_owned(),
            database: "eliot".to_owned(),
            username: "store".to_owned(),
            connect_timeout_ms: 1_000,
            query_timeout_ms: 1_000,
            schema_generation: "1.0.0".to_owned(),
            blob_root: r"C:\ProgramData\Eliot\blob".to_owned(),
            instance_id: "store-test".to_owned(),
            credential_ref: "eliot/store".to_owned(),
        };
        config.approved_config_hash = launch_config_digest(&config).expect("config digest");
        config
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
}
