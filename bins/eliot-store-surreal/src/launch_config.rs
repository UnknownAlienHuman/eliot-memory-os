//! Store launch configuration and validation.
//!
//! Architecture (verified):
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.A2.3`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.A12.3`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.A13.2`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-MOD-02`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-SEC-02`
//! - `eliot-architecture-docs-fa941135.ELIOT_ARCHITECTURE.ARCH-RES-01`
//!
//! Implementation (verified):
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I1.2`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I2.2`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I2.23`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I5.9`
//! - `eliot-architecture-docs-fa941135.ELIOT_IMPLEMENTATION.I15.3`
//!
//! This module owns Store launch configuration validation, materialization,
//! digest binding, and bounded JSON/TOML loading only. It forbids runtime
//! composition, semantic readiness, authority ownership, and provider lifecycle.

#![forbid(unsafe_code)]

use std::path::Path;

use eliot_installation::{
    PHASE_B_PENDING_SCM_DIGEST, RuntimeLaunchDescriptor, validate_store_credential_target,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{UserOwnedPathLease, UserOwnedRootLease, read_protected_file};
use eliot_runtime_contracts::RuntimeLiveStoreIdentity;
use eliot_store_surreal_adapter::SchemaGeneration;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_LAUNCH_CONFIG_BYTES: u64 = 256 * 1024;
pub(crate) const LEGACY_PHASE_B_ZERO_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreLaunchConfig {
    pub store_pipe: String,
    pub launch_nonce: String,
    pub expected_client_sid: String,
    pub expected_client_session_id: u32,
    pub approved_artifact_hash: String,
    pub approved_config_hash: String,
    pub endpoint: String,
    pub provider_bind_address: String,
    pub namespace: String,
    pub database: String,
    pub username: String,
    pub connect_timeout_ms: u64,
    pub query_timeout_ms: u64,
    pub schema_generation: String,
    pub blob_root: String,
    pub instance_id: String,
    pub credential_ref: String,
    pub runtime_launch: RuntimeLaunchDescriptor,
}

impl StoreLaunchConfig {
    pub fn validate(&self) -> Result<(), String> {
        validate_launch_text(&self.store_pipe, "store_pipe")?;
        validate_launch_text(&self.launch_nonce, "launch_nonce")?;
        eliot_ipc::validate_pipe_name(&self.store_pipe)
            .map_err(|error| format!("invalid store_pipe: {error}"))?;
        eliot_platform_windows::NamedPipePeerExpectation::new(
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
        self.runtime_launch
            .validate()
            .map_err(|error| format!("invalid runtime_launch: {error}"))?;
        validate_store_credential_target(&self.credential_ref)
            .map_err(|reason| format!("invalid credential_ref: {reason}"))?;
        if self.credential_ref != self.runtime_launch.store_credential_target.as_str() {
            return Err(
                "credential_ref must exactly equal runtime_launch.store_credential_target"
                    .to_owned(),
            );
        }
        if self.approved_artifact_hash != self.runtime_launch.store_bridge_artifact_digest.as_str()
        {
            return Err(
                "approved_artifact_hash must equal runtime_launch.store_bridge_artifact_digest"
                    .to_owned(),
            );
        }
        validate_launch_text(&self.endpoint, "endpoint")?;
        validate_provider_bind_address(&self.provider_bind_address)?;
        if self.endpoint != format!("ws://{}/rpc", self.provider_bind_address) {
            return Err(
                "endpoint must exactly match the explicit loopback provider bind address"
                    .to_owned(),
            );
        }
        if !RuntimeLiveStoreIdentity::canonical().is_exact_match(
            &self.provider_bind_address,
            &self.endpoint,
            &self.namespace,
        ) {
            return Err(
                "Store launch target must exactly match the canonical runtime-live bind, endpoint, and namespace"
                    .to_owned(),
            );
        }
        let descriptor_provider_arguments = self
            .runtime_launch
            .canonical_store_arguments
            .iter()
            .map(|argument| argument.as_str().to_owned())
            .collect::<Vec<_>>();
        if descriptor_provider_arguments != expected_provider_arguments(self) {
            return Err(
                "runtime_launch canonical provider argv does not exactly match Store coordinates"
                    .to_owned(),
            );
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

    pub fn validate_materialized_at(&self, config_path: &Path) -> Result<(), String> {
        self.validate()?;
        if !config_path.is_absolute() {
            return Err("materialized Store config path must be absolute".to_owned());
        }
        let config_path = PlatformHandle::new(config_path.to_string_lossy().into_owned())
            .map_err(|error| format!("invalid materialized Store config path: {error}"))?;
        self.runtime_launch
            .validate_for_config(&config_path)
            .map_err(|error| format!("runtime launch/config materialization mismatch: {error}"))
    }

    pub(crate) const fn authority_epoch(&self) -> u64 {
        self.runtime_launch
            .authority_state_fence
            .authority_epoch
            .value()
    }

    pub(crate) const fn store_generation(&self) -> u64 {
        self.runtime_launch.authority_generation.value()
    }
}

fn expected_provider_arguments(config: &StoreLaunchConfig) -> Vec<String> {
    let roots = &config.runtime_launch.runtime_state_roots;
    vec![
        "start".to_owned(),
        "--no-banner".to_owned(),
        "--bind".to_owned(),
        config.provider_bind_address.clone(),
        "--temporary-directory".to_owned(),
        roots.store_temp_root.as_str().to_owned(),
        "--log-file-enabled".to_owned(),
        "--log-file-path".to_owned(),
        roots.store_work_root.as_str().to_owned(),
        "--log-file-name".to_owned(),
        "surrealdb.log".to_owned(),
        format!(
            "surrealkv://{}",
            roots.store_data_root.as_str().replace('\\', "/")
        ),
    ]
}

pub fn launch_config_digest(config: &StoreLaunchConfig) -> Result<String, String> {
    #[derive(Serialize)]
    struct OperationalConfig<'a> {
        store_pipe: &'a str,
        launch_nonce: &'a str,
        expected_client_sid: &'a str,
        expected_client_session_id: u32,
        approved_artifact_hash: &'a str,
        endpoint: &'a str,
        provider_bind_address: &'a str,
        namespace: &'a str,
        database: &'a str,
        username: &'a str,
        connect_timeout_ms: u64,
        query_timeout_ms: u64,
        schema_generation: &'a str,
        blob_root: &'a str,
        instance_id: &'a str,
        credential_ref: &'a str,
        runtime_launch: &'a RuntimeLaunchDescriptor,
    }
    let input = OperationalConfig {
        store_pipe: &config.store_pipe,
        launch_nonce: &config.launch_nonce,
        expected_client_sid: &config.expected_client_sid,
        expected_client_session_id: config.expected_client_session_id,
        approved_artifact_hash: &config.approved_artifact_hash,
        endpoint: &config.endpoint,
        provider_bind_address: &config.provider_bind_address,
        namespace: &config.namespace,
        database: &config.database,
        username: &config.username,
        connect_timeout_ms: config.connect_timeout_ms,
        query_timeout_ms: config.query_timeout_ms,
        schema_generation: &config.schema_generation,
        blob_root: &config.blob_root,
        instance_id: &config.instance_id,
        credential_ref: &config.credential_ref,
        runtime_launch: &config.runtime_launch,
    };
    let bytes =
        serde_json::to_vec(&input).map_err(|error| format!("serialize launch digest: {error}"))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

pub(crate) fn validate_digest(value: &str, field: &str) -> Result<(), String> {
    if value == PHASE_B_PENDING_SCM_DIGEST {
        return Err(format!(
            "{field} cannot use the adapter-only SCM pending selector"
        ));
    }
    if value == LEGACY_PHASE_B_ZERO_DIGEST {
        return Err(format!("{field} cannot use the legacy zero runtime digest"));
    }
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("{field} must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

pub(crate) fn validate_launch_text(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(format!(
            "{field} must be non-blank and contain no control characters"
        ));
    }
    Ok(())
}

fn validate_provider_bind_address(value: &str) -> Result<(), String> {
    let port = value
        .strip_prefix("127.0.0.1:")
        .or_else(|| value.strip_prefix("[::1]:"))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0);
    if port.is_none() {
        return Err(
            "provider_bind_address must be an explicit non-zero loopback socket".to_owned(),
        );
    }
    Ok(())
}

pub fn load_config(path: Option<&Path>) -> Result<StoreLaunchConfig, String> {
    let Some(path) = path else {
        return Err("--config is required; launch config must be explicit".to_owned());
    };
    let bytes = read_protected_file(path, MAX_LAUNCH_CONFIG_BYTES)
        .map_err(|error| format!("read protected config: {error}"))?;
    parse_config_bytes(path, &bytes)
}

pub fn load_portable_dev_config(
    root: &UserOwnedRootLease,
    path: &Path,
) -> Result<StoreLaunchConfig, String> {
    let lease = UserOwnedPathLease::open_existing(root, path)
        .map_err(|error| format!("open portable-dev config: {error}"))?;
    let bytes = lease
        .read_bounded(MAX_LAUNCH_CONFIG_BYTES)
        .map_err(|error| format!("read portable-dev config: {error}"))?;
    parse_config_bytes(path, &bytes)
}

pub(crate) fn parse_config_bytes(path: &Path, bytes: &[u8]) -> Result<StoreLaunchConfig, String> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => {
            let config: StoreLaunchConfig = serde_json::from_slice(bytes)
                .map_err(|error| format!("parse JSON config: {error}"))?;
            config.validate_materialized_at(path)?;
            Ok(config)
        }
        Some("toml") => {
            let config: StoreLaunchConfig =
                toml::from_slice(bytes).map_err(|error| format!("parse TOML config: {error}"))?;
            config.validate_materialized_at(path)?;
            Ok(config)
        }
        Some(extension) => Err(format!(
            "config extension must be .json or .toml, got .{extension}"
        )),
        None => Err("config path must have a .json or .toml extension".to_owned()),
    }
}
