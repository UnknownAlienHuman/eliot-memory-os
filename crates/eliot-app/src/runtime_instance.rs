use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub(crate) const PUBLICATION_SCHEMA_VERSION: &str = "eliot-runtime-publication-v1";
pub(crate) const DEFAULT_INSTANCE_NAME: &str = "default";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeInstance {
    name: String,
    publication_root: PathBuf,
    standalone: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimePublicationState {
    Starting,
    Ready,
    Failed,
    Stopping,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimePublication {
    pub schema_version: String,
    pub protocol_version: String,
    pub instance_name: String,
    pub runtime_id: String,
    pub auth_generation: String,
    pub pipe_name: String,
    pub daemon_pid: u32,
    pub process_start_identity: String,
    pub executable: PathBuf,
    pub config_path: PathBuf,
    pub store_root: PathBuf,
    pub publication_root: PathBuf,
    pub state: RuntimePublicationState,
    pub auth_ref: PathBuf,
    pub published_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeDiscoveryErrorCode {
    PublicationMissing,
    PublicationUnreadable,
    PublicationSchemaMismatch,
    PublicationInstanceMismatch,
    PublicationRootMismatch,
    PublicationProtocolMismatch,
    PublicationPipeMismatch,
    PublicationIdentityInvalid,
    PublicationNotReady,
    AuthenticationReferenceMismatch,
    AuthenticationFileMissing,
    AuthenticationFileUnreadable,
    AuthenticationFieldMismatch,
}

#[derive(Debug)]
pub(crate) struct RuntimeDiscoveryError {
    pub code: RuntimeDiscoveryErrorCode,
    pub detail: String,
}

impl fmt::Display for RuntimeDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "runtime discovery {:?}: {}",
            self.code, self.detail
        )
    }
}

impl std::error::Error for RuntimeDiscoveryError {}

impl RuntimeInstance {
    pub(crate) fn select(config_path: &Path, selector: Option<&str>) -> Result<Self> {
        if let Some(name) = selector {
            validate_instance_name(name)?;
            Ok(Self {
                name: name.to_owned(),
                publication_root: eliot_home()?.join("instances").join(name),
                standalone: true,
            })
        } else {
            let publication_root = config_runtime_root(config_path);
            let identity = path_identity(&publication_root);
            let digest = blake3::hash(identity.as_bytes()).to_hex();
            Ok(Self {
                name: format!("isolated-{}", &digest[..12]),
                publication_root,
                standalone: false,
            })
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn publication_root(&self) -> &Path {
        &self.publication_root
    }

    pub(crate) const fn standalone(&self) -> bool {
        self.standalone
    }

    pub(crate) fn runtime_dir(&self) -> PathBuf {
        self.publication_root.join("runtime")
    }

    pub(crate) fn publication_path(&self) -> PathBuf {
        self.runtime_dir().join("publication.json")
    }

    pub(crate) fn authentication_path(&self) -> PathBuf {
        self.runtime_dir().join("ipc-auth.json")
    }

    pub(crate) fn startup_diagnostic_path(&self) -> PathBuf {
        self.publication_root
            .join("reports")
            .join("startup")
            .join("latest.json")
    }

    pub(crate) fn stop_marker(&self) -> PathBuf {
        self.runtime_dir().join("stop.requested")
    }

    pub(crate) fn pipe_name(&self) -> String {
        let digest = blake3::hash(path_identity(&self.publication_root).as_bytes()).to_hex();
        format!(r"\\.\pipe\eliot-governor-{}", &digest[..20])
    }

    pub(crate) fn starting_publication(
        &self,
        protocol_version: &str,
        config_path: &Path,
        store_root: &Path,
    ) -> Result<RuntimePublication> {
        let runtime_id = Uuid::now_v7().to_string();
        let executable = std::env::current_exe()
            .context("resolve current Eliot executable")?
            .canonicalize()
            .unwrap_or_else(|_| std::env::current_exe().unwrap_or_default());
        let published_at = time::OffsetDateTime::now_utc().to_string();
        Ok(RuntimePublication {
            schema_version: PUBLICATION_SCHEMA_VERSION.to_owned(),
            protocol_version: protocol_version.to_owned(),
            instance_name: self.name.clone(),
            runtime_id: runtime_id.clone(),
            auth_generation: Uuid::now_v7().to_string(),
            pipe_name: self.pipe_name(),
            daemon_pid: std::process::id(),
            process_start_identity: format!(
                "pid:{}:runtime:{}:started:{}",
                std::process::id(),
                runtime_id,
                published_at
            ),
            executable,
            config_path: absolute_path(config_path),
            store_root: absolute_path(store_root),
            publication_root: absolute_path(&self.publication_root),
            state: RuntimePublicationState::Starting,
            auth_ref: absolute_path(&self.authentication_path()),
            published_at,
        })
    }

    pub(crate) fn publish(&self, publication: &RuntimePublication) -> Result<()> {
        fs::create_dir_all(self.runtime_dir())?;
        atomic_write_json(&self.publication_path(), publication)
    }

    pub(crate) fn publish_state(
        &self,
        publication: &mut RuntimePublication,
        state: RuntimePublicationState,
    ) -> Result<()> {
        publication.state = state;
        publication.published_at = time::OffsetDateTime::now_utc().to_string();
        self.publish(publication)
    }

    pub(crate) fn read_publication(
        &self,
        expected_protocol: &str,
    ) -> std::result::Result<RuntimePublication, RuntimeDiscoveryError> {
        let publication = self.read_publication_any_state(expected_protocol)?;
        if publication.state != RuntimePublicationState::Ready {
            return Err(RuntimeDiscoveryError {
                code: RuntimeDiscoveryErrorCode::PublicationNotReady,
                detail: format!("runtime state is {:?}", publication.state),
            });
        }
        Ok(publication)
    }

    pub(crate) fn read_publication_any_state(
        &self,
        expected_protocol: &str,
    ) -> std::result::Result<RuntimePublication, RuntimeDiscoveryError> {
        let path = self.publication_path();
        let bytes = fs::read(&path).map_err(|error| RuntimeDiscoveryError {
            code: if error.kind() == std::io::ErrorKind::NotFound {
                RuntimeDiscoveryErrorCode::PublicationMissing
            } else {
                RuntimeDiscoveryErrorCode::PublicationUnreadable
            },
            detail: format!("{}: {error}", path.display()),
        })?;
        let publication =
            serde_json::from_slice::<RuntimePublication>(&bytes).map_err(|error| {
                RuntimeDiscoveryError {
                    code: RuntimeDiscoveryErrorCode::PublicationUnreadable,
                    detail: format!("{}: {error}", path.display()),
                }
            })?;
        self.validate_publication(&publication, expected_protocol)?;
        Ok(publication)
    }

    pub(crate) fn cleanup_owned(&self, owner: &RuntimePublication) -> Result<bool> {
        let Ok(current) = self.read_publication_any_state(&owner.protocol_version) else {
            return Ok(false);
        };
        if current.runtime_id != owner.runtime_id
            || current.auth_generation != owner.auth_generation
        {
            return Ok(false);
        }
        for path in [self.authentication_path(), self.publication_path()] {
            if path.is_file() {
                fs::remove_file(path)?;
            }
        }
        Ok(true)
    }

    pub(crate) fn record_startup_failure(
        &self,
        expected_protocol: &str,
        detail: &str,
    ) -> Result<()> {
        atomic_write_json(
            &self.startup_diagnostic_path(),
            &serde_json::json!({
                "component": "runtime_startup_diagnostic",
                "status": "failed",
                "instance": self.name,
                "publication_root": self.publication_root,
                "daemon_pid": std::process::id(),
                "error": detail,
                "recorded_at": time::OffsetDateTime::now_utc().to_string()
            }),
        )?;
        if let Ok(mut publication) = self.read_publication_any_state(expected_protocol)
            && publication.daemon_pid == std::process::id()
        {
            self.publish_state(&mut publication, RuntimePublicationState::Failed)?;
        }
        Ok(())
    }

    fn validate_publication(
        &self,
        publication: &RuntimePublication,
        expected_protocol: &str,
    ) -> std::result::Result<(), RuntimeDiscoveryError> {
        let mismatch = |code, detail| RuntimeDiscoveryError { code, detail };
        if publication.schema_version != PUBLICATION_SCHEMA_VERSION {
            return Err(mismatch(
                RuntimeDiscoveryErrorCode::PublicationSchemaMismatch,
                format!(
                    "expected {PUBLICATION_SCHEMA_VERSION}, got {}",
                    publication.schema_version
                ),
            ));
        }
        if publication.instance_name != self.name {
            return Err(mismatch(
                RuntimeDiscoveryErrorCode::PublicationInstanceMismatch,
                format!("expected {}, got {}", self.name, publication.instance_name),
            ));
        }
        if path_identity(&publication.publication_root) != path_identity(&self.publication_root) {
            return Err(mismatch(
                RuntimeDiscoveryErrorCode::PublicationRootMismatch,
                format!(
                    "expected {}, got {}",
                    self.publication_root.display(),
                    publication.publication_root.display()
                ),
            ));
        }
        if publication.protocol_version != expected_protocol {
            return Err(mismatch(
                RuntimeDiscoveryErrorCode::PublicationProtocolMismatch,
                format!(
                    "expected {expected_protocol}, got {}",
                    publication.protocol_version
                ),
            ));
        }
        if publication.pipe_name != self.pipe_name() {
            return Err(mismatch(
                RuntimeDiscoveryErrorCode::PublicationPipeMismatch,
                format!(
                    "expected {}, got {}",
                    self.pipe_name(),
                    publication.pipe_name
                ),
            ));
        }
        if publication.daemon_pid == 0
            || Uuid::parse_str(&publication.runtime_id).is_err()
            || Uuid::parse_str(&publication.auth_generation).is_err()
            || publication.process_start_identity.trim().is_empty()
            || !publication
                .process_start_identity
                .contains(&publication.runtime_id)
            || !publication.executable.is_absolute()
            || !publication.config_path.is_absolute()
            || !publication.store_root.is_absolute()
        {
            return Err(mismatch(
                RuntimeDiscoveryErrorCode::PublicationIdentityInvalid,
                "runtime identity, PID, executable, config, or store root is invalid".to_owned(),
            ));
        }
        if path_identity(&publication.auth_ref) != path_identity(&self.authentication_path()) {
            return Err(mismatch(
                RuntimeDiscoveryErrorCode::AuthenticationReferenceMismatch,
                format!(
                    "expected {}, got {}",
                    self.authentication_path().display(),
                    publication.auth_ref.display()
                ),
            ));
        }
        Ok(())
    }
}

pub(crate) fn default_config_path() -> Result<PathBuf> {
    Ok(eliot_home()?.join("config").join("governor.toml"))
}

pub(crate) fn config_runtime_root(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(".eliot-governor"))
        .to_path_buf()
}

pub(crate) fn store_root_from_storage(storage: &str) -> PathBuf {
    storage
        .strip_prefix("rocksdb:")
        .and_then(|path| Path::new(path).parent())
        .map_or_else(|| PathBuf::from(".eliot-governor"), Path::to_path_buf)
}

pub(crate) fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    atomic_write_bytes(path, &serde_json::to_vec_pretty(value)?)
}

pub(crate) fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("atomic write path has no parent")?;
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("eliot"),
        Uuid::new_v4()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    eliot_windows_ipc::atomic_replace_file(&temp, path)
        .with_context(|| format!("atomically replace {}", path.display()))?;
    #[cfg(not(windows))]
    fs::rename(&temp, path)?;
    Ok(())
}

pub(crate) fn path_identity(path: &Path) -> String {
    let absolute = fs::canonicalize(path).unwrap_or_else(|_| absolute_path(path));
    let text = absolute.to_string_lossy();
    let normalized = text
        .strip_prefix(r"\\?\UNC\")
        .map_or_else(
            || text.strip_prefix(r"\\?\").map(str::to_owned),
            |rest| Some(format!(r"\\{rest}")),
        )
        .unwrap_or_else(|| text.into_owned());
    normalized.replace('/', "\\").to_ascii_lowercase()
}

fn absolute_path(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

fn eliot_home() -> Result<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .context("LOCALAPPDATA is required for a standalone Eliot instance")?;
    Ok(local_app_data.join("Eliot"))
}

fn validate_instance_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        anyhow::bail!("instance name must be 1-64 ASCII letters, digits, dot, dash, or underscore");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RuntimeInstance, path_identity};
    use std::fs;
    use std::path::Path;

    #[test]
    fn windows_verbatim_prefix_does_not_change_identity() {
        assert_eq!(
            path_identity(Path::new(r"C:\Profiles\Example\Eliot")),
            path_identity(Path::new(r"\\?\C:\Profiles\Example\Eliot"))
        );
    }

    #[test]
    fn existing_windows_path_aliases_share_identity() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "eliot-runtime-path-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir_all(&root)?;
        let canonical = fs::canonicalize(&root)?;

        assert_eq!(path_identity(&root), path_identity(&canonical));

        fs::remove_dir_all(&canonical)?;
        Ok(())
    }

    #[test]
    fn invalid_instance_selector_is_rejected() {
        assert!(
            RuntimeInstance::select(Path::new("config/governor.toml"), Some("../bad")).is_err()
        );
    }
}
