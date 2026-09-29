//! Store launch configuration and validation.
//!
//! Architecture: `A2.3` (`docs/architecture/A02-03-modular-architecture.md`),
//! `A12.3` (`docs/architecture/A12-03-one-governed-write-path.md`), and `A13.2`
//! (`docs/architecture/A13-02-kernel-and-failure-domains.md`), plus Decision
//! Anchors `docs/architecture/A16-01-decision-anchors.md` `ARCH-MOD-02`,
//! `ARCH-SEC-02`, and `ARCH-RES-01`. Implementation: `I1.2`
//! (`docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md`),
//! `I2.23`
//! (`docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`),
//! `I5.9` (`docs/architecture/I05-09-surrealdb-implementation.md`), and `I15.3`
//! (`docs/architecture/I15-03-least-privilege-processes.md`). Normative
//! precedence remains in `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! This module owns Store launch configuration validation, materialization,
//! digest binding, and bounded JSON/TOML loading only. It forbids runtime
//! composition, semantic readiness, authority ownership, and provider lifecycle.

#![forbid(unsafe_code)]

use std::path::{Component, Path};

use eliot_installation::{
    PHASE_B_PENDING_SCM_DIGEST, RuntimeLaunchDescriptor,
    validate_provider_bootstrap_credential_target, validate_store_credential_target,
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
    /// Kernel-configured store transaction limit bounding canonical-write
    /// concurrency (I5.7, issue #1933). `None` keeps the I5.7 desktop default;
    /// an explicit value must be non-zero and is digest-bound below. Absent
    /// on the wire means default; both approved-digest projections omit an
    /// unset knob identically, so legacy approvals stay byte-stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_transaction_limit: Option<usize>,
    pub schema_generation: String,
    pub blob_root: String,
    pub instance_id: String,
    pub credential_ref: String,
    /// Reserved Credential Manager reference for the provider child's own
    /// bootstrap/admin credential (I15.4). It is a different reference from
    /// [`Self::credential_ref`] so the two can be rotated independently, and
    /// it never carries a value: this configuration is a secret-free launch
    /// declaration.
    pub provider_bootstrap_credential_ref: String,
    /// `SurrealDB` identity whose credential the provider child consumes. It
    /// must not be the ordinary client [`Self::username`].
    pub provider_bootstrap_username: String,
    pub runtime_launch: RuntimeLaunchDescriptor,
}

impl StoreLaunchConfig {
    pub fn validate(&self) -> Result<(), String> {
        // One finite production boundary map (issue #1810) decides which
        // contours may hold a database credential and which owns the provider
        // endpoint; this launch must resolve to exactly that assignment.
        crate::boundary_map::StoreBoundaryMap::canonical().validate_against(self)?;
        validate_launch_text(&self.store_pipe, "store_pipe")?;
        validate_launch_text(&self.launch_nonce, "launch_nonce")?;
        // #726: the typed namespace owner decides the legacy/current boundary
        // first, so a recognized historical identity is routed through the
        // owner-approved legacy mapping decision instead of being classified
        // only by the current-namespace prefix check below.
        refuse_legacy_pipe_namespace(&self.store_pipe)?;
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
        self.validate_provider_credential_boundary()?;
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
        if self.store_transaction_limit == Some(0) {
            return Err("store_transaction_limit must be non-zero".to_owned());
        }
        SchemaGeneration::new(self.schema_generation.as_str())
            .map_err(|error| format!("invalid schema_generation: {error}"))?;
        if !Path::new(&self.blob_root).is_absolute()
            || Path::new(&self.blob_root)
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(
                "blob_root must be an absolute path without relative components".to_owned(),
            );
        }
        self.validate_blob_root_binding()?;
        Ok(())
    }

    /// Refuses a Blob root that aliases a `SurrealKV` runtime root (issue #19).
    ///
    /// This runs inside [`StoreLaunchConfig::validate`], hence before the
    /// composition claims the Blob root owner and materializes the adapter, so
    /// one directory can never receive two owners through this launch path.
    fn validate_blob_root_binding(&self) -> Result<(), String> {
        let roots = &self.runtime_launch.runtime_state_roots;
        if let Some(field) = blob_root_alias_field(
            &self.blob_root,
            roots.store_data_root.as_str(),
            roots.store_work_root.as_str(),
            roots.store_temp_root.as_str(),
        ) {
            return Err(format!(
                "blob_root must not alias the SurrealKV {field}; one directory has one owner"
            ));
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

    /// Validates the provider bootstrap/admin credential boundary of this
    /// launch (I15.4).
    ///
    /// The provider child and the Store bridge must be admitted to two
    /// different reserved credential references carrying two different
    /// `SurrealDB` identities. A shared reference, or a bootstrap identity
    /// equal to the ordinary client identity, would collapse the separation
    /// into one credential; it is refused here rather than at provider
    /// start-up, where the failure would already have launched the provider.
    fn validate_provider_credential_boundary(&self) -> Result<(), String> {
        validate_launch_text(
            &self.provider_bootstrap_credential_ref,
            "provider_bootstrap_credential_ref",
        )?;
        validate_launch_text(
            &self.provider_bootstrap_username,
            "provider_bootstrap_username",
        )?;
        validate_provider_bootstrap_credential_target(&self.provider_bootstrap_credential_ref)
            .map_err(|reason| format!("invalid provider_bootstrap_credential_ref: {reason}"))?;
        // The two references must differ; `StoreBoundaryMap::validate_against`
        // owns that admission and runs first in `validate`.
        if self.provider_bootstrap_username == self.username {
            return Err(
                "provider_bootstrap_username must be a distinct identity from username".to_owned(),
            );
        }
        Ok(())
    }

    pub(crate) const fn authority_epoch(&self) -> u64 {
        self.runtime_launch
            .authority_state_fence
            .authority_epoch
            .sequence
            .get()
    }

    pub(crate) const fn store_generation(&self) -> u64 {
        self.runtime_launch.authority_generation.value()
    }
}

/// Routes a legacy `eliot-governor-<digest>` pipe identity through the typed
/// namespace owner's legacy→current mapping decision, and refuses it when no
/// owner-approved mapping exists.
///
/// Issue #726 makes `eliot-protocol`'s typed owner the single enforcement point
/// for the complete ELIOT named-pipe namespace. A persisted Store launch config
/// is a real producer of pipe identities, so a recognized historical identity
/// is offered to that owner's mapping decision
/// ([`eliot_protocol::LegacyEliotPipeName::map_to_current`], delegating to
/// [`eliot_protocol::EliotPipeOwner::map_legacy_to_current`]) rather than being
/// classified only by the current-namespace prefix check.
///
/// This runs before the current-namespace check on purpose. The exact
/// `\\.\pipe\eliot\` prefix carries its trailing separator, so it does not
/// match `\\.\pipe\eliot-governor-`: a legacy identity would otherwise be
/// rejected only as an unprefixed name, with no owner decision recorded and no
/// migration path owned.
///
/// Current names are unaffected. A current name is not a legacy identity, so
/// [`eliot_protocol::LegacyEliotPipeName::parse`] reports
/// [`eliot_protocol::EliotPipeNameError::LegacyUnsupported`] and this returns
/// `Ok`, leaving the unchanged current-namespace acceptance and bytes to
/// `eliot_ipc::validate_pipe_name`. A recognized legacy identity reaches the
/// owner, which refuses it until the actual endpoint owner supplies an
/// explicitly inventoried versioned mapping; no mapping is invented here and
/// the two names are never both probed. Name validity is identity only — it
/// never authenticates a peer, admits an ACL, or grants permission to connect.
fn refuse_legacy_pipe_namespace(store_pipe: &str) -> Result<(), String> {
    let Ok(legacy) = eliot_protocol::LegacyEliotPipeName::parse(store_pipe) else {
        return Ok(());
    };
    legacy
        .map_to_current()
        .map(|_current| ())
        .map_err(|error| format!("invalid store_pipe: {error}"))
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
        // Omitted when unset so legacy approved bytes stay unchanged; an
        // explicit limit is encoded identically here and in the installer
        // projection (`PlannerOperationalConfig`).
        #[serde(skip_serializing_if = "Option::is_none")]
        store_transaction_limit: Option<usize>,
        schema_generation: &'a str,
        blob_root: &'a str,
        instance_id: &'a str,
        credential_ref: &'a str,
        provider_bootstrap_credential_ref: &'a str,
        provider_bootstrap_username: &'a str,
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
        store_transaction_limit: config.store_transaction_limit,
        schema_generation: &config.schema_generation,
        blob_root: &config.blob_root,
        instance_id: &config.instance_id,
        credential_ref: &config.credential_ref,
        provider_bootstrap_credential_ref: &config.provider_bootstrap_credential_ref,
        provider_bootstrap_username: &config.provider_bootstrap_username,
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

/// Names the `SurrealKV` runtime root aliased by `blob_root`, if any.
///
/// The Blob writer and the provider child must never share one directory
/// identity: an aliased root would place the Blob lease file and the provider
/// files under one tree, defeating the one-active-owner exclusion each lease
/// proves separately. Comparison runs over the same normalized identity the
/// adapter uses for its runtime roots, so separator, case, and trailing-slash
/// respellings of one directory are still refused.
fn blob_root_alias_field(
    blob_root: &str,
    store_data_root: &str,
    store_work_root: &str,
    store_temp_root: &str,
) -> Option<&'static str> {
    let blob = normalize_launch_root(blob_root);
    for (field, root) in [
        ("store_data_root", store_data_root),
        ("store_work_root", store_work_root),
        ("store_temp_root", store_temp_root),
    ] {
        if blob == normalize_launch_root(root) {
            return Some(field);
        }
    }
    None
}

fn normalize_launch_root(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
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

/// Loads one explicit `UserMode` Store config through the admitted
/// immutable-binaries root. The caller supplies that root from the Host launch
/// selection; this loader never derives it from the process environment or
/// current directory.
pub fn load_user_mode_config(
    root: &UserOwnedRootLease,
    path: &Path,
) -> Result<StoreLaunchConfig, String> {
    let lease = UserOwnedPathLease::open_existing(root, path)
        .map_err(|error| format!("open UserMode config: {error}"))?;
    let bytes = lease
        .read_bounded(MAX_LAUNCH_CONFIG_BYTES)
        .map_err(|error| format!("read UserMode config: {error}"))?;
    let config = parse_config_bytes(path, &bytes)?;
    if config.runtime_launch.profile != eliot_installation::InstallationProfile::UserMode {
        return Err("UserMode launch config does not select the UserMode profile".to_owned());
    }
    validate_user_mode_launch_root_binding(root, &config)?;
    Ok(config)
}

/// Verifies that a current-user retained root is the exact immutable launch
/// root in the admitted descriptor. Store's `generation.json` is materialized
/// beside the selected immutable binaries; the user configuration and cache
/// roles remain separate profile roots.
pub fn validate_user_mode_launch_root_binding(
    root: &UserOwnedRootLease,
    config: &StoreLaunchConfig,
) -> Result<(), String> {
    if config.runtime_launch.profile != eliot_installation::InstallationProfile::UserMode {
        return Err("user-owned launch roots are only admitted for UserMode".to_owned());
    }
    root.verify_stable_identity()
        .and_then(|()| root.verify_path_identity())
        .map_err(|error| format!("revalidate user-owned config root: {error}"))?;
    let admitted_root = Path::new(
        &config.runtime_launch.profile_governed_roots.immutable_binaries,
    );
    if !eliot_platform_windows::windows_paths_equal(root.path(), admitted_root) {
        return Err(
            "retained launch root does not match the descriptor immutable_binaries root"
                .to_owned(),
        );
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_root_alias_is_refused_across_separator_case_and_trailing_slash() {
        let data = r"C:\ProgramData\Eliot\store\data";
        assert_eq!(
            blob_root_alias_field(data, data, "w", "t"),
            Some("store_data_root")
        );
        assert_eq!(
            blob_root_alias_field("c:/programdata/eliot/store/data/", data, "w", "t"),
            Some("store_data_root")
        );
        assert_eq!(
            blob_root_alias_field(r"C:\ProgramData\Eliot\blob", data, "w", "t"),
            None
        );
    }
}
