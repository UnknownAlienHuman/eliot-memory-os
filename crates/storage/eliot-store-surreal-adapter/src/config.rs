//! Connection, credential and schema-generation configuration for the `SurrealDB`
//! store bridge.
//!
//! The credential is held as a [`secrecy::SecretString`] and is never placed in
//! debug output, logs, reports, canonical memory or a serialized form. The
//! config is assembled programmatically by the composition owner (the store
//! bridge); it is not a TOML/JSON projection.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::SecretString;

use crate::error::AdapterError;

/// Stable identity of this adapter surface.
pub const ADAPTER_NAME: &str = "eliot.storage.store-surreal-adapter";
/// `SurrealDB` major version admitted by the pinned adapter/query surface.
pub const PINNED_SURREALDB_MAJOR: u16 = 3;

/// Non-blank, non-control-character schema generation identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct SchemaGeneration(String);

impl SchemaGeneration {
    /// Constructs a valid schema generation identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, SchemaGenerationError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(SchemaGenerationError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn v2() -> Self {
        Self("2.0.0".to_owned())
    }

    /// Returns the stable generation identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemaGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Failure to construct a [`SchemaGeneration`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SchemaGenerationError {
    #[error("schema generation must be non-blank and contain no control characters")]
    Invalid,
}

/// Connection and credential settings for the sole `SurrealDB` client owner.
///
/// The password is the only credential value held by this crate. It is redacted
/// by [`secrecy::SecretString`] in debug formatting and is never serialized.
#[derive(Clone)]
pub struct SurrealAdapterConfig {
    /// `SurrealDB` WebSocket endpoint, for example `ws://127.0.0.1:18000/rpc`.
    pub endpoint: String,
    /// `SurrealDB` namespace.
    pub namespace: String,
    /// `SurrealDB` database.
    pub database: String,
    /// `SurrealDB` username used for sign-in.
    pub username: String,
    /// `SurrealDB` password credential, held opaque and redacted.
    pub password: SecretString,
    /// Exact loopback address owned by this adapter's provider child.
    pub provider_bind_address: String,
    /// Canonical installation identity that owns the provider roots.
    pub installation_id: String,
    /// Canonical installation profile (`system_service`, `user_mode`, or
    /// `portable_dev`).
    pub installation_profile: String,
    /// Digest of the complete canonical `RuntimeStateRoots` projection.
    pub runtime_state_roots_digest: String,
    /// Installation-approved canonical `surreal.exe` path.
    pub provider_executable_path: String,
    /// Installation-approved SHA-256 of the canonical provider executable.
    pub provider_artifact_digest: String,
    /// Descriptor-bound canonical provider argv, excluding argv[0].
    pub provider_arguments: Vec<String>,
    /// Canonical `SurrealKV` data root.
    pub store_data_root: String,
    /// Canonical provider working/log root.
    pub store_work_root: String,
    /// Canonical provider temporary-file root.
    pub store_temp_root: String,
    /// Connect deadline in milliseconds.
    pub connect_timeout_ms: u64,
    /// Query deadline in milliseconds.
    pub query_timeout_ms: u64,
    /// `SurrealDB` server major version required by the pinned query surface.
    pub expected_provider_major: u16,
    /// Schema generation this bridge expects the database to be migrated to.
    pub expected_schema_generation: SchemaGeneration,
}

impl fmt::Debug for SurrealAdapterConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SurrealAdapterConfig")
            .field("endpoint", &self.endpoint)
            .field("namespace", &self.namespace)
            .field("database", &self.database)
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("provider_bind_address", &self.provider_bind_address)
            .field("installation_id", &self.installation_id)
            .field("installation_profile", &self.installation_profile)
            .field(
                "runtime_state_roots_digest",
                &self.runtime_state_roots_digest,
            )
            .field("provider_executable_path", &self.provider_executable_path)
            .field("provider_artifact_digest", &self.provider_artifact_digest)
            .field("provider_arguments", &self.provider_arguments)
            .field("store_data_root", &self.store_data_root)
            .field("store_work_root", &self.store_work_root)
            .field("store_temp_root", &self.store_temp_root)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("query_timeout_ms", &self.query_timeout_ms)
            .field("expected_provider_major", &self.expected_provider_major)
            .field(
                "expected_schema_generation",
                &self.expected_schema_generation,
            )
            .finish()
    }
}

impl SurrealAdapterConfig {
    /// Validates the non-secret configuration fields without inspecting the
    /// credential value.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let endpoint = self.endpoint.trim();
        validate_provider_bind_address(&self.provider_bind_address)?;
        if endpoint != format!("ws://{}/rpc", self.provider_bind_address) {
            return Err(ConfigError::InvalidEndpoint);
        }
        validate_name(&self.namespace, "namespace")?;
        validate_name(&self.database, "database")?;
        validate_name(&self.username, "username")?;
        validate_name(&self.installation_id, "installation_id")?;
        if !matches!(
            self.installation_profile.as_str(),
            "system_service" | "user_mode" | "portable_dev"
        ) {
            return Err(ConfigError::InvalidField {
                field: "installation_profile",
            });
        }
        validate_digest(
            &self.runtime_state_roots_digest,
            "runtime_state_roots_digest",
        )?;
        validate_digest(&self.provider_artifact_digest, "provider_artifact_digest")?;
        let executable = Path::new(&self.provider_executable_path);
        if !executable.is_absolute()
            || executable
                .file_name()
                .and_then(|name| name.to_str())
                .is_none_or(|name| !name.eq_ignore_ascii_case("surreal.exe"))
        {
            return Err(ConfigError::InvalidField {
                field: "provider_executable_path",
            });
        }
        let roots = [
            ("store_data_root", self.store_data_root.as_str()),
            ("store_work_root", self.store_work_root.as_str()),
            ("store_temp_root", self.store_temp_root.as_str()),
        ];
        for (field, value) in roots {
            validate_root(value, field)?;
        }
        let normalized = roots.map(|(_, value)| normalize_root(value));
        if normalized[0] == normalized[1]
            || normalized[0] == normalized[2]
            || normalized[1] == normalized[2]
        {
            return Err(ConfigError::AliasedRuntimeRoots);
        }
        if self.provider_arguments != self.expected_provider_arguments() {
            return Err(ConfigError::InvalidField {
                field: "provider_arguments",
            });
        }
        if self.connect_timeout_ms == 0 || self.query_timeout_ms == 0 {
            return Err(ConfigError::InvalidTimeout);
        }
        if self.expected_provider_major != PINNED_SURREALDB_MAJOR {
            return Err(ConfigError::UnsupportedProviderMajor {
                expected: PINNED_SURREALDB_MAJOR,
            });
        }
        if self.expected_schema_generation.as_str() != crate::schema::GENERATION_V2 {
            return Err(ConfigError::InvalidField {
                field: "expected_schema_generation",
            });
        }
        Ok(())
    }

    /// Returns the one canonical provider argv implied by the validated Store
    /// roots and loopback bind address.
    #[must_use]
    pub fn expected_provider_arguments(&self) -> Vec<String> {
        vec![
            "start".to_owned(),
            "--no-banner".to_owned(),
            "--bind".to_owned(),
            self.provider_bind_address.clone(),
            "--temporary-directory".to_owned(),
            self.store_temp_root.clone(),
            "--log-file-enabled".to_owned(),
            "--log-file-path".to_owned(),
            self.store_work_root.clone(),
            "--log-file-name".to_owned(),
            "surrealdb.log".to_owned(),
            format!("surrealkv://{}", self.store_data_root.replace('\\', "/")),
        ]
    }

    /// Re-proves that a retained data-root lease was claimed for exactly this
    /// configuration's `store_data_root`.
    ///
    /// The lease identity (canonical path plus owner token) travels alongside
    /// `store_data_root` as validated configuration: it is checked after the
    /// lease claim before the provider spawn gap, and rechecked on every
    /// transport-liveness validation, so a lease can never drift onto a
    /// different root than the one it excludes. A second configuration sharing
    /// one data root with distinct work roots fails here or at claim time with
    /// a typed denial.
    pub(crate) fn validate_data_root_lease(
        &self,
        lease: &StoreDataRootLease,
    ) -> Result<(), AdapterError> {
        if self.store_data_root != lease.configured_root {
            return Err(AdapterError::Config(
                "store data root lease is not bound to the configured store data root".to_owned(),
            ));
        }
        let (_, identity) = resolve_data_root(&self.store_data_root, false)?;
        if identity != lease.root_identity
            || lease.owner_token.trim().is_empty()
            || lease.process_id == 0
        {
            return Err(AdapterError::Config(
                "store data root lease is not bound to the configured store data root".to_owned(),
            ));
        }
        Ok(())
    }
}

/// OS-exclusion lease file proving exclusive ownership of one `SurrealKV` data root.
pub(crate) const STORE_DATA_ROOT_LEASE_FILE: &str = ".eliot-store-data-root.lock";

/// Windows reparse-point attribute flag used to reject symlinked data roots.
#[cfg(windows)]
const WINDOWS_REPARSE_POINT: u32 = 0x400;

/// Win32 sharing-violation code: a takeover open failing with this code proves a
/// live owner still holds its unshareable lease handle.
#[cfg(windows)]
const WINDOWS_SHARING_VIOLATION: i32 = 32;

static DATA_ROOT_LEASE_TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Same-process registry of claimed canonical data-root identities. This is only
/// a secondary defense: cross-process exclusion is enforced by the unshareable OS
/// handle each lease holds for its full lifetime.
static PROCESS_DATA_ROOT_CLAIMS: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

/// Exclusive process-owned claim on one canonical `SurrealKV` data root.
///
/// This is the adapter-native analogue of the proven `BlobRootOwner` exclusion
/// pattern, implemented for a directory root with only `std` primitives: the claim
/// is backed by an OS-visible lease file inside the canonicalized data root, and
/// the owner holds the OS file handle for its full lifetime. A second
/// bridge/provider generation that configures the same data root — even with a
/// distinct work root — fails lease acquisition with a typed denial instead of
/// spawning a second `surreal.exe` against the same files.
///
/// The OS handle is the authority. A crashed owner releases the claim when the OS
/// closes the handle; the next claimer then takes over by reopening and rewriting
/// the informational record. The lock path is never unlinked, which would
/// reintroduce an unlink race. No heartbeat is required: a live owner always holds
/// an unshareable handle, so a takeover open can succeed only when no live owner
/// exists. The record content is informational only and is never trusted for an
/// ownership decision.
pub(crate) struct StoreDataRootLease {
    configured_root: String,
    root_identity: String,
    canonical_root: PathBuf,
    owner_token: String,
    process_id: u32,
    lock_file: std::fs::File,
}

impl fmt::Debug for StoreDataRootLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreDataRootLease")
            .field("configured_root", &self.configured_root)
            .field("root_identity", &self.root_identity)
            .field("canonical_root", &self.canonical_root)
            .field("owner_token", &"[REDACTED]")
            .field("process_id", &self.process_id)
            .field("lock_file", &self.lock_file)
            .finish()
    }
}

impl Drop for StoreDataRootLease {
    fn drop(&mut self) {
        // The OS handle close is the cross-process release; this only clears the
        // secondary same-process registry. Never unlink the lock path.
        if let Some(registry) = PROCESS_DATA_ROOT_CLAIMS.get()
            && let Ok(mut claims) = registry.lock()
        {
            claims.remove(&self.root_identity);
        }
    }
}

impl StoreDataRootLease {
    /// Claims exclusive ownership of the canonical data root named by
    /// `store_data_root`. The OS handle is held for the lease lifetime, so a
    /// second claimer on the same root — in this process or another — receives
    /// an `AdapterError::Config` denial.
    pub(crate) fn claim(store_data_root: &str) -> Result<Self, AdapterError> {
        let process_id = std::process::id();
        let (canonical_root, root_identity) = resolve_data_root(store_data_root, true)?;
        let lock_path = canonical_root.join(STORE_DATA_ROOT_LEASE_FILE);
        reject_lease_path_reparse(&lock_path)?;
        let mut lock_file = open_data_root_lease(&lock_path)?;
        let owner_token = lease_token(process_id);
        write_lease_record(&mut lock_file, &root_identity, &owner_token, process_id)?;
        // The OS exclusion above is the primary authority; the same-process set
        // below only names the conflict deterministically inside one process.
        let registry = PROCESS_DATA_ROOT_CLAIMS.get_or_init(|| Mutex::new(BTreeSet::new()));
        let mut claims = registry.lock().map_err(|_| {
            AdapterError::Config("store data root claim registry is unavailable".to_owned())
        })?;
        if !claims.insert(root_identity.clone()) {
            return Err(AdapterError::Config(
                "store data root is already owned by another bridge generation in this process"
                    .to_owned(),
            ));
        }
        Ok(Self {
            configured_root: store_data_root.to_owned(),
            root_identity,
            canonical_root,
            owner_token,
            process_id,
            lock_file,
        })
    }
}

/// Canonicalizes `store_data_root` to its directory identity, creating the
/// directory only for the initial claim. Reparse points anywhere on the
/// configured or canonical path are rejected: the lease must pin the real
/// directory the provider will open, never a link that could alias two roots.
fn resolve_data_root(
    configured_root: &str,
    create: bool,
) -> Result<(PathBuf, String), AdapterError> {
    if configured_root.trim().is_empty() || configured_root.chars().any(char::is_control) {
        return Err(AdapterError::Config(
            "store data root claim requires a non-blank root".to_owned(),
        ));
    }
    let configured = PathBuf::from(configured_root);
    if !configured.is_absolute()
        || configured
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(AdapterError::Config(
            "store data root must be an absolute path without relative components".to_owned(),
        ));
    }
    if create {
        std::fs::create_dir_all(&configured).map_err(|_| {
            AdapterError::Config("store data root directory could not be created".to_owned())
        })?;
    }
    let metadata = std::fs::symlink_metadata(&configured).map_err(|_| {
        AdapterError::Config("store data root directory could not be inspected".to_owned())
    })?;
    if !metadata.is_dir() {
        return Err(AdapterError::Config(
            "store data root must resolve to a directory".to_owned(),
        ));
    }
    reject_reparse_ancestors(&configured)?;
    let canonical = std::fs::canonicalize(&configured).map_err(|_| {
        AdapterError::Config("store data root could not be canonicalized".to_owned())
    })?;
    reject_reparse_ancestors(&canonical)?;
    let identity = canonical_data_root_identity(&canonical);
    Ok((canonical, identity))
}

fn canonical_data_root_identity(canonical: &Path) -> String {
    let mut identity = canonical.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        identity.make_ascii_lowercase();
    }
    identity
}

fn reject_reparse_ancestors(path: &Path) -> Result<(), AdapterError> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if let Ok(metadata) = std::fs::symlink_metadata(candidate)
            && is_data_root_reparse(&metadata)
        {
            return Err(AdapterError::Config(
                "store data root with reparse components is not permitted".to_owned(),
            ));
        }
        current = candidate.parent();
    }
    Ok(())
}

fn reject_lease_path_reparse(lock_path: &Path) -> Result<(), AdapterError> {
    match std::fs::symlink_metadata(lock_path) {
        Ok(metadata) if is_data_root_reparse(&metadata) => Err(AdapterError::Config(
            "store data root lease reparse points are not permitted".to_owned(),
        )),
        Ok(_) | Err(_) => Ok(()),
    }
}

fn is_data_root_reparse(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::MetadataExt::file_attributes(metadata) & WINDOWS_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
fn open_data_root_lease(lock_path: &Path) -> Result<std::fs::File, AdapterError> {
    use std::os::windows::fs::OpenOptionsExt;

    let mut exclusive = std::fs::OpenOptions::new();
    exclusive
        .create_new(true)
        .read(true)
        .write(true)
        .share_mode(0);
    match exclusive.open(lock_path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // A crashed owner leaves the record but not the handle. Reopening the
            // existing path with zero sharing transfers ownership, while a live
            // owner denies this open with a sharing violation.
            let mut takeover = std::fs::OpenOptions::new();
            takeover.read(true).write(true).share_mode(0);
            takeover.open(lock_path).map_err(|takeover_error| {
                if is_sharing_denial(&takeover_error) {
                    AdapterError::Config(
                        "store data root is already owned by another bridge generation; two generations cannot open the same production data root"
                            .to_owned(),
                    )
                } else {
                    AdapterError::Config(
                        "store data root lease could not be reopened after a prior owner record"
                            .to_owned(),
                    )
                }
            })
        }
        Err(_) => Err(AdapterError::Config(
            "store data root lease file could not be created".to_owned(),
        )),
    }
}

#[cfg(not(windows))]
fn open_data_root_lease(lock_path: &Path) -> Result<std::fs::File, AdapterError> {
    // The production runtime is native Windows. On other targets, fail closed on
    // an existing lease path rather than pretending portable `std::fs` semantics
    // provide equivalent cross-process exclusion.
    std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                AdapterError::Config(
                    "store data root is already owned by another bridge generation; two generations cannot open the same production data root"
                        .to_owned(),
                )
            } else {
                AdapterError::Config(
                    "store data root lease file could not be created".to_owned(),
                )
            }
        })
}

#[cfg(windows)]
fn is_sharing_denial(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::AlreadyExists
    ) || error.raw_os_error() == Some(WINDOWS_SHARING_VIOLATION)
}

fn lease_token(process_id: u32) -> String {
    let sequence = DATA_ROOT_LEASE_TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{process_id}-{}-{sequence}", now_unix_ms())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn write_lease_record(
    lock_file: &mut std::fs::File,
    root_identity: &str,
    owner_token: &str,
    process_id: u32,
) -> Result<(), AdapterError> {
    use std::io::{Seek, Write};

    lock_file.set_len(0).map_err(|_| {
        AdapterError::Config("store data root lease record could not be written".to_owned())
    })?;
    lock_file.rewind().map_err(|_| {
        AdapterError::Config("store data root lease record could not be written".to_owned())
    })?;
    write!(
        lock_file,
        "eliot-store-data-root-lease-v1\nroot={root_identity}\ntoken={owner_token}\nprocess={process_id}\n"
    )
    .map_err(|_| {
        AdapterError::Config("store data root lease record could not be written".to_owned())
    })?;
    lock_file.flush().map_err(|_| {
        AdapterError::Config("store data root lease record could not be written".to_owned())
    })?;
    Ok(())
}

fn validate_name(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ConfigError::InvalidField { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ConfigError::InvalidField { field });
    }
    Ok(())
}

fn validate_provider_bind_address(value: &str) -> Result<(), ConfigError> {
    let port = value
        .strip_prefix("127.0.0.1:")
        .or_else(|| value.strip_prefix("[::1]:"))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0);
    if port.is_none() {
        return Err(ConfigError::InvalidField {
            field: "provider_bind_address",
        });
    }
    Ok(())
}

fn validate_root(value: &str, field: &'static str) -> Result<(), ConfigError> {
    validate_name(value, field)?;
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ConfigError::InvalidField { field });
    }
    Ok(())
}

fn normalize_root(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

/// Configuration failure without exposing the credential value.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConfigError {
    #[error("endpoint must exactly match the explicit loopback provider bind address")]
    InvalidEndpoint,
    #[error("timeouts must be non-zero")]
    InvalidTimeout,
    #[error("provider major version must be the pinned SurrealDB {expected}.x line")]
    UnsupportedProviderMajor { expected: u16 },
    #[error("invalid field {field}")]
    InvalidField { field: &'static str },
    #[error("Store data, work, and temp roots must be distinct")]
    AliasedRuntimeRoots,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use secrecy::SecretString;

    use super::*;

    fn config(endpoint: &str) -> SurrealAdapterConfig {
        SurrealAdapterConfig {
            endpoint: endpoint.to_owned(),
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
    fn schema_generation_rejects_blank_and_control() {
        assert!(SchemaGeneration::new("").is_err());
        assert!(SchemaGeneration::new("  ").is_err());
        assert!(SchemaGeneration::new("bad\nvalue").is_err());
        assert!(SchemaGeneration::new("1.0.0").is_ok());
    }

    #[test]
    fn schema_generation_accepts_v2() {
        assert!(SchemaGeneration::new("2.0.0").is_ok());
        assert!(SchemaGeneration::new(crate::schema::GENERATION_V2).is_ok());
    }

    #[test]
    fn config_validates_endpoint_and_names() {
        assert!(config("ws://127.0.0.1:18000/rpc").validate().is_ok());
        assert!(config("http://example.com").validate().is_err());
        assert!(config("nonsense").validate().is_err());
        let mut mismatched = config("ws://127.0.0.1:18000/rpc");
        mismatched.provider_bind_address = "127.0.0.1:19000".to_owned();
        assert!(mismatched.validate().is_err());
    }

    #[test]
    fn debug_output_redacts_the_password() {
        let rendered = format!("{:?}", config("ws://127.0.0.1:18000/rpc"));
        assert!(!rendered.contains("test-secret"));
        assert!(!rendered.contains("provider-user"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn config_rejects_root_aliases_relative_roots_and_bad_digests() {
        let mut aliased = config("ws://127.0.0.1:18000/rpc");
        aliased.store_temp_root = aliased.store_data_root.clone();
        assert_eq!(aliased.validate(), Err(ConfigError::AliasedRuntimeRoots));

        let mut relative = config("ws://127.0.0.1:18000/rpc");
        relative.store_work_root = r"store\work".to_owned();
        assert!(relative.validate().is_err());

        let mut bad_digest = config("ws://127.0.0.1:18000/rpc");
        bad_digest.runtime_state_roots_digest = "unknown".to_owned();
        assert!(bad_digest.validate().is_err());
    }

    #[test]
    fn expected_generation_must_be_exact_v2() {
        let mut cfg = config("ws://127.0.0.1:18000/rpc");
        assert!(cfg.validate().is_ok());
        cfg.expected_schema_generation = SchemaGeneration::new("1.0.0").expect("valid");
        assert_eq!(
            cfg.validate(),
            Err(ConfigError::InvalidField {
                field: "expected_schema_generation"
            })
        );
        cfg.expected_schema_generation = SchemaGeneration::v2();
        assert!(cfg.validate().is_ok());
        cfg.expected_schema_generation = SchemaGeneration::new("2.0.1").expect("valid");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn readiness_oracle_v1_requires_migration_v2_is_ready() {
        let expected = SchemaGeneration::v2();
        assert_eq!(expected.as_str(), crate::schema::GENERATION_V2);
        let observed_v1 = Some(crate::schema::GENERATION_V1.to_owned());
        let observed_v2 = Some(crate::schema::GENERATION_V2.to_owned());
        assert_ne!(observed_v1, Some(expected.as_str().to_owned()));
        assert_eq!(observed_v2, Some(expected.as_str().to_owned()));
    }
}
