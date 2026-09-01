//! Adapter configuration materialization cell for `eliot-store-surreal`.
//!
//! Architecture: `docs/architecture/ELIOT_ARCHITECTURE.md` R2 Canonical
//! substrate, `ARCH-AUTH-01` explicit scoped authority, `ARCH-SEC-02` one
//! canonical transition path, and `ARCH-RES-01` local failure/global recovery.
//! Implementation: `docs/architecture/ELIOT_IMPLEMENTATION.md:I2.23`
//! capability-family topology and crate extraction decisions, plus the
//! Store/provider credential boundary (`StoreLaunchConfig`/`credential_ref`
//! through Windows Credential Manager `read_credential` versus provider
//! `SurrealAdapterConfig`/`password` separation).
//!
//! This cell materializes provider configuration and credentials only; it owns no
//! canonical/semantic authority, defaults, retries, Store writes, or readiness
//! inference. Normative precedence remains in `docs/ARCHITECTURE_CONTRACT.md`.

use eliot_installation::InstallationProfile;
use eliot_platform_windows::WindowsPlatform;
use eliot_store_surreal_adapter::{PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig};
use secrecy::SecretString;

use crate::StoreLaunchConfig;

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

pub(crate) fn resolve_credential(
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
