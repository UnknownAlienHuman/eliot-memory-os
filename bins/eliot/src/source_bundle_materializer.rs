#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use eliot_governor::{GovernorLaunchConfig, KernelGenerationExpectation};
use eliot_installation::{
    AuthorityEpoch, GenerationPackagePlanner, InstallationEpoch, InstallationError,
    InstallationProfile, LOCAL_SERVICE_SID, PHASE_B_PENDING_MARKER, PackageArtifactDigest,
    PlatformHandle, ResourceGeneration, RuntimeLaunchDescriptor, RuntimeStateRoots, StateFence,
    SupervisionAuthorityBinding,
};
use eliot_kernel_service::EliotdLaunchDescriptor;
use eliot_platform_windows::{
    AuthenticodeEvidence, AuthenticodeVerifier, DirectoryPublicationOutcome,
    DirectoryPublicationReceipt, FileIdentity, OwnedDirectoryPublication, PackageFileSpec,
    PackageManifest, PeCoffEvidence, TrustedSourceBundle, WindowsAuthenticodeVerifier,
    parse_pe_coff, validate_package_relative_path,
};
use eliot_store_surreal::{StoreLaunchConfig, launch_config_digest};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_EXECUTABLE_BYTES: usize = 512 * 1024 * 1024;
const ELIOTD_LAUNCH_DESCRIPTOR_WIRE_ID: &str = "eliot.kernel.eliotd-launch";

/// The only source roles admitted to Phase A.
///
/// `authority.json` and `store-bootstrap.json` are intentionally absent. They
/// are Host-owned Phase-B material and can never be supplied by this command.
pub const REQUIRED_ROLES: [(&str, bool); 9] = [
    ("eliot-host.exe", true),
    ("eliot-watchdog.exe", true),
    ("eliot-kernel.exe", true),
    ("eliot-store-surreal.exe", true),
    ("surreal.exe", true),
    ("eliotd.exe", true),
    ("generation.json", false),
    ("eliotd-governor.json", false),
    ("eliotd.json", false),
];

/// Explicit inputs for one immutable source-bundle publication.
#[derive(Clone, Debug)]
pub struct CanarySourceBundleMaterializeInput {
    /// Release `eliot-host.exe` path.
    pub eliot_host_exe: PathBuf,
    /// Release `eliot-watchdog.exe` path.
    pub eliot_watchdog_exe: PathBuf,
    /// Release `eliot-kernel.exe` path.
    pub eliot_kernel_exe: PathBuf,
    /// Release `eliot-store-surreal.exe` path.
    pub eliot_store_surreal_exe: PathBuf,
    /// Release `surreal.exe` path.
    pub surreal_exe: PathBuf,
    /// Release `eliotd.exe` path.
    pub eliotd_exe: PathBuf,
    /// Absent absolute directory to create exactly once.
    pub output_bundle: PathBuf,
    /// Canonical relative generation identity.
    pub generation: PlatformHandle,
    /// Installation lineage used by the typed launch contracts.
    pub installation_epoch: InstallationEpoch,
    /// Explicit installation profile.
    pub profile: InstallationProfile,
    /// OS-validated profile anchor supplied by the caller.
    pub profile_anchor_root: PlatformHandle,
    /// Lowercase installation key for profiled roots.
    pub installation_key: Option<PlatformHandle>,
    /// Stable transaction identity used by the planner's launch-template
    /// derivation.
    pub transaction_id: PlatformHandle,
    /// Explicit destination staging root used by the existing Generate path.
    pub staging_root: PlatformHandle,
}

/// One receipt fact for a published source role.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedRoleReceipt {
    /// Canonical Phase-A role name.
    pub relative_path: String,
    /// Whether this role is an executable.
    pub executable: bool,
    /// Exact bytes published.
    pub size: u64,
    /// Lowercase SHA-256 of the exact bytes published.
    pub sha256: String,
    /// Identity before immutable publication.
    pub source_identity: FileIdentity,
    /// Identity after immutable publication.
    pub destination_identity: FileIdentity,
    /// PE evidence for executable roles.
    pub pe: Option<PeCoffEvidence>,
    /// Authenticode evidence for executable roles.
    pub authenticode: Option<AuthenticodeEvidence>,
}

/// Exact role facts measured in the owned temporary tree before commit.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedRolePrecommitReceipt {
    /// Canonical Phase-A role name.
    pub relative_path: String,
    /// Whether this role is an executable.
    pub executable: bool,
    /// Exact bytes measured before commit.
    pub size: u64,
    /// Lowercase SHA-256 of those exact bytes.
    pub sha256: String,
    /// Identity of the caller-supplied release file, or the generated JSON
    /// file when the role has no external source.
    pub source_identity: FileIdentity,
    /// Identity of the role file in the owned temporary directory.
    pub temporary_identity: FileIdentity,
    /// PE evidence for executable roles.
    pub pe: Option<PeCoffEvidence>,
    /// Authenticode evidence for executable roles.
    pub authenticode: Option<AuthenticodeEvidence>,
}

/// Receipt for one successful immutable source-bundle publication.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanarySourceBundleReceipt {
    /// Absolute published bundle path.
    pub bundle_path: String,
    /// Canonical relative generation identity.
    pub generation: String,
    /// Full nine-role canonical artifact evidence digest.
    pub evidence_digest: String,
    /// Exact role inventory, identities and byte facts.
    pub files: Vec<MaterializedRoleReceipt>,
    /// Identity of the published bundle directory.
    pub source_identity: FileIdentity,
    /// Exact directory create-new publication receipt.
    pub directory_publication: DirectoryPublicationReceipt,
}

/// The non-wire proof handed directly to the generation planner.  It carries
/// only the exact published root identity, ordered nine-role byte facts and
/// full evidence digest; the planner independently reopens and observes the
/// path before accepting these facts.
#[derive(Clone, Debug)]
pub(crate) struct SourceBundlePublicationBinding {
    pub source_identity: FileIdentity,
    pub files: Vec<PackageArtifactDigest>,
    pub evidence_digest: PlatformHandle,
}

impl CanarySourceBundleReceipt {
    pub(crate) fn planner_binding(
        &self,
    ) -> Result<SourceBundlePublicationBinding, MaterializeError> {
        if self.files.len() != REQUIRED_ROLES.len()
            || self.source_identity != self.directory_publication.source_identity
            || self.source_identity != self.directory_publication.destination_identity
        {
            return Err(MaterializeError::Invalid(
                "published source receipt is not an exact nine-role directory publication"
                    .to_owned(),
            ));
        }
        let files = self
            .files
            .iter()
            .map(|file| {
                Ok(PackageArtifactDigest {
                    relative_path: file.relative_path.clone(),
                    expected_size: file.size,
                    sha256: PlatformHandle::new(file.sha256.clone()).map_err(|error| {
                        MaterializeError::Contract(format!(
                            "source publication digest {}: {error}",
                            file.relative_path
                        ))
                    })?,
                })
            })
            .collect::<Result<Vec<_>, MaterializeError>>()?;
        let evidence_digest =
            PlatformHandle::new(self.evidence_digest.clone()).map_err(|error| {
                MaterializeError::Contract(format!("source evidence digest: {error}"))
            })?;
        Ok(SourceBundlePublicationBinding {
            source_identity: self.source_identity,
            files,
            evidence_digest,
        })
    }
}

/// Materializer-level reason a committed directory cannot yet feed Generate.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanarySourceBundleReconciliationReason {
    /// The platform move committed but exact directory receipt readback was
    /// unavailable.
    DirectoryPublicationUnknown,
    /// Directory publication was exact, but the complete nine-role
    /// post-commit source-bundle readback was rejected.
    PostCommitBundleReadbackRejected,
}

/// Durable reconciliation record for a committed source-bundle move.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanarySourceBundleReconciliation {
    /// Canonical intended bundle path.
    pub bundle_path: String,
    /// Canonical relative generation identity.
    pub generation: String,
    /// Full nine-role canonical artifact evidence digest.
    pub evidence_digest: String,
    /// Complete role facts measured before the atomic commit.
    pub precommit_files: Vec<MaterializedRolePrecommitReceipt>,
    /// Exact platform result, including source and parent identities.
    pub directory_publication: DirectoryPublicationOutcome,
    /// Why normal receipt promotion and Generate were withheld.
    pub reason: CanarySourceBundleReconciliationReason,
    /// Non-authoritative bounded diagnostic for operator triage.
    pub diagnostic: String,
}

/// Result of attempting one immutable source-bundle materialization.
#[derive(Clone, Debug, Serialize)]
pub enum CanarySourceBundleMaterializeOutcome {
    /// Full pre-commit and post-commit role readback passed.
    Published(CanarySourceBundleReceipt),
    /// The move committed, but Generate must wait for reconciliation.
    CommittedUnknown(CanarySourceBundleReconciliation),
}

#[derive(Debug, thiserror::Error)]
pub enum MaterializeError {
    #[error("materialize invalid: {0}")]
    Invalid(String),
    #[error("materialize platform: {0}")]
    Platform(String),
    #[error("materialize typed contract rejected: {0}")]
    Contract(String),
}

impl From<MaterializeError> for InstallationError {
    fn from(value: MaterializeError) -> Self {
        match value {
            MaterializeError::Invalid(reason) => Self::InvalidField {
                field: "source_bundle_materialize".to_owned(),
                reason,
            },
            MaterializeError::Platform(reason) => Self::Platform(reason),
            MaterializeError::Contract(reason) => Self::InvalidField {
                field: "source_bundle_materialize.typed_contract".to_owned(),
                reason,
            },
        }
    }
}

#[derive(Clone, Debug)]
struct ValidatedExecutable {
    name: &'static str,
    bytes: Vec<u8>,
    size: u64,
    sha256: String,
    identity: FileIdentity,
    pe: PeCoffEvidence,
    authenticode: AuthenticodeEvidence,
}

#[derive(Clone, Debug)]
struct JsonRole {
    name: &'static str,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct TypedBundle {
    json_roles: Vec<JsonRole>,
    expected: Vec<PackageArtifactDigest>,
    manifest: PackageManifest,
    evidence_digest: PlatformHandle,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_absolute(path: &Path, field: &str) -> Result<(), MaterializeError> {
    if !path.is_absolute() {
        return Err(MaterializeError::Invalid(format!(
            "{field} must be absolute"
        )));
    }
    let raw = path.to_string_lossy();
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("\\\\?\\")
        || lower.starts_with("\\\\.\\")
        || lower.starts_with("\\??\\")
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(MaterializeError::Invalid(format!(
            "{field} contains a forbidden prefix or traversal"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse(path: &Path) -> Result<bool, MaterializeError> {
    use std::os::windows::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    Ok(metadata.file_attributes() & 0x400 != 0)
}

#[cfg(not(windows))]
fn is_reparse(path: &Path) -> Result<bool, MaterializeError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    Ok(metadata.file_type().is_symlink())
}

fn handle_path(path: &Path, field: &str) -> Result<PlatformHandle, MaterializeError> {
    validate_absolute(path, field)?;
    PlatformHandle::new(path.to_string_lossy().into_owned())
        .map_err(|error| MaterializeError::Invalid(format!("{field}: {error}")))
}

fn to_installation_error(error: MaterializeError) -> InstallationError {
    error.into()
}

fn validate_executable(
    path: &Path,
    expected_name: &'static str,
) -> Result<ValidatedExecutable, MaterializeError> {
    validate_absolute(path, expected_name)?;
    if is_reparse(path)? {
        return Err(MaterializeError::Invalid(format!(
            "{expected_name} is a reparse point"
        )));
    }
    let actual_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if actual_name != expected_name {
        return Err(MaterializeError::Invalid(format!(
            "{expected_name} filename mismatch: {actual_name}"
        )));
    }
    let metadata = fs::metadata(path)
        .map_err(|error| MaterializeError::Platform(format!("open {expected_name}: {error}")))?;
    if !metadata.is_file() {
        return Err(MaterializeError::Invalid(format!(
            "{expected_name} is not a regular file"
        )));
    }
    let bytes = fs::read(path)
        .map_err(|error| MaterializeError::Platform(format!("read {expected_name}: {error}")))?;
    if bytes.is_empty() || bytes.len() > MAX_EXECUTABLE_BYTES {
        return Err(MaterializeError::Invalid(format!(
            "{expected_name} size is outside the bounded executable range"
        )));
    }
    let sha256 = sha256_hex(&bytes);
    let pe = parse_pe_coff(&bytes[..bytes.len().min(1024 * 1024)]).map_err(|error| {
        MaterializeError::Invalid(format!(
            "{expected_name} PE/COFF validation failed: {error}"
        ))
    })?;
    if pe.machine != 0x8664 || !pe.pe32_plus {
        return Err(MaterializeError::Invalid(format!(
            "{expected_name} must be AMD64 PE32+"
        )));
    }
    let identity = eliot_platform_windows::file_identity_for_path(path)
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    if identity.volume_serial_number == 0 || identity.file_index == 0 {
        return Err(MaterializeError::Invalid(format!(
            "{expected_name} identity is zero"
        )));
    }
    let authenticode = WindowsAuthenticodeVerifier
        .verify(path, identity, &sha256)
        .map_err(|error| {
            MaterializeError::Invalid(format!("{expected_name} Authenticode failed: {error}"))
        })?;
    if authenticode.verdict != eliot_platform_windows::AuthenticodeVerdict::Valid {
        return Err(MaterializeError::Invalid(format!(
            "{expected_name} Authenticode verdict is not Valid: {:?}",
            authenticode.verdict
        )));
    }

    // Re-read after the signature check. The immutable publication receives
    // only bytes whose identity and digest still equal the verified object.
    let reread = fs::read(path)
        .map_err(|error| MaterializeError::Platform(format!("re-read {expected_name}: {error}")))?;
    let reread_identity = eliot_platform_windows::file_identity_for_path(path)
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    if reread_identity != identity || sha256_hex(&reread) != sha256 {
        return Err(MaterializeError::Invalid(format!(
            "{expected_name} changed after Authenticode validation"
        )));
    }

    Ok(ValidatedExecutable {
        name: expected_name,
        size: bytes.len() as u64,
        bytes,
        sha256,
        identity,
        pe,
        authenticode,
    })
}

fn validate_role_inventory(roles: &[(&str, bool)]) -> Result<(), MaterializeError> {
    if roles.len() != REQUIRED_ROLES.len() {
        return Err(MaterializeError::Invalid(
            "Phase-A source bundle must contain exactly nine roles".to_owned(),
        ));
    }
    for (actual, expected) in roles.iter().zip(REQUIRED_ROLES) {
        if actual != &expected {
            return Err(MaterializeError::Invalid(format!(
                "role inventory must be the exact ordered nine-role Phase-A set; got {}",
                actual.0
            )));
        }
    }
    Ok(())
}

fn derive_runtime_roots(
    profile: InstallationProfile,
    profile_anchor_root: &PlatformHandle,
    installation_key: Option<&PlatformHandle>,
) -> Result<RuntimeStateRoots, MaterializeError> {
    match profile {
        InstallationProfile::PortableDev => {
            if installation_key.is_some() {
                return Err(MaterializeError::Invalid(
                    "portable_dev must not provide installation_key".to_owned(),
                ));
            }
            RuntimeStateRoots::derive_portable(profile_anchor_root.clone())
                .map_err(|error| MaterializeError::Contract(error.to_string()))
        }
        InstallationProfile::SystemService | InstallationProfile::UserMode => {
            let key = installation_key.ok_or_else(|| {
                MaterializeError::Invalid(
                    "profiled installation requires installation_key".to_owned(),
                )
            })?;
            RuntimeStateRoots::derive_profiled(profile, profile_anchor_root.clone(), key.as_str())
                .map_err(|error| MaterializeError::Contract(error.to_string()))
        }
    }
}

fn make_digest(value: String, field: &str) -> Result<PlatformHandle, MaterializeError> {
    PlatformHandle::new(value)
        .map_err(|error| MaterializeError::Contract(format!("{field}: {error}")))
}

fn make_args(
    values: impl IntoIterator<Item = String>,
) -> Result<Vec<PlatformHandle>, MaterializeError> {
    values
        .into_iter()
        .map(|value| {
            PlatformHandle::new(value)
                .map_err(|error| MaterializeError::Contract(format!("runtime argument: {error}")))
        })
        .collect()
}

fn package_digest(
    relative_path: &'static str,
    size: u64,
    sha256: &str,
) -> Result<PackageArtifactDigest, MaterializeError> {
    Ok(PackageArtifactDigest {
        relative_path: relative_path.to_owned(),
        expected_size: size,
        sha256: make_digest(sha256.to_owned(), "package digest")?,
    })
}

fn validate_store_config_bytes(
    bytes: &[u8],
    expected_launch: &RuntimeLaunchDescriptor,
) -> Result<StoreLaunchConfig, MaterializeError> {
    let config: StoreLaunchConfig = serde_json::from_slice(bytes)
        .map_err(|error| MaterializeError::Contract(format!("generation.json: {error}")))?;
    config
        .validate_materialized_at(Path::new(expected_launch.store_config_path.as_str()))
        .map_err(|error| MaterializeError::Contract(format!("generation.json: {error}")))?;
    if config.runtime_launch != *expected_launch {
        return Err(MaterializeError::Contract(
            "generation.json runtime_launch is not the exact planner template".to_owned(),
        ));
    }
    Ok(config)
}

fn governor_bytes(
    generation: &PlatformHandle,
    installation_epoch: &InstallationEpoch,
    kernel_sha256: &str,
) -> Result<Vec<u8>, MaterializeError> {
    let generation_number = ResourceGeneration::new(1)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let authority_epoch =
        AuthorityEpoch::new(1).map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let protected = sha256_hex(
        format!(
            "governor-protected:{}:{}:{}",
            installation_epoch.installation.as_str(),
            generation.as_str(),
            kernel_sha256
        )
        .as_bytes(),
    );
    let config = GovernorLaunchConfig {
        instance_id: format!("eliotd-{}", generation.as_str()),
        kernel: KernelGenerationExpectation {
            service: "eliot-kernel".to_owned(),
            protocol: "eliot.kernel.v1".to_owned(),
            artifact_digest: kernel_sha256.to_owned(),
            protected_snapshot_digest: protected.clone(),
            principal: LOCAL_SERVICE_SID.to_owned(),
            generation: generation_number,
            authority_epoch,
        },
        protected_snapshot_digest: protected,
    };
    config
        .validate()
        .map_err(|error| MaterializeError::Contract(format!("eliotd-governor.json: {error}")))?;
    serde_json::to_vec(&config)
        .map_err(|error| MaterializeError::Contract(format!("serialize governor config: {error}")))
}

#[allow(
    clippy::too_many_lines,
    reason = "the typed bundle seam keeps all launch and evidence bindings auditable"
)]
fn build_typed_bundle(
    input: &CanarySourceBundleMaterializeInput,
    executables: &[ValidatedExecutable],
) -> Result<TypedBundle, MaterializeError> {
    let roots = derive_runtime_roots(
        input.profile,
        &input.profile_anchor_root,
        input.installation_key.as_ref(),
    )?;
    let generation_root = Path::new(input.staging_root.as_str()).join(input.generation.as_str());
    let role_path = |role: &str| handle_path(&generation_root.join(role), "staging destination");
    let host_path = role_path("eliot-host.exe")?;
    let watchdog_path = role_path("eliot-watchdog.exe")?;
    let store_bridge_path = role_path("eliot-store-surreal.exe")?;
    let canonical_store_path = role_path("surreal.exe")?;
    let eliotd_path = role_path("eliotd.exe")?;
    let config_path = role_path("generation.json")?;
    let governor_path = role_path("eliotd-governor.json")?;
    let descriptor_path = role_path("eliotd.json")?;
    let authority_path = role_path("authority.json")?;
    let store_bootstrap_path = role_path("store-bootstrap.json")?;

    let by_name = |name: &str| {
        executables
            .iter()
            .find(|item| item.name == name)
            .ok_or_else(|| MaterializeError::Invalid(format!("missing executable {name}")))
    };
    let kernel = by_name("eliot-kernel.exe")?;
    let host = by_name("eliot-host.exe")?;
    let watchdog = by_name("eliot-watchdog.exe")?;
    let store_bridge = by_name("eliot-store-surreal.exe")?;
    let canonical_store = by_name("surreal.exe")?;
    let eliotd = by_name("eliotd.exe")?;
    let governor = governor_bytes(&input.generation, &input.installation_epoch, &kernel.sha256)?;
    let governor_sha256 = sha256_hex(&governor);
    let template_facts = vec![
        package_digest("eliot-host.exe", host.size, &host.sha256)?,
        package_digest("eliot-watchdog.exe", watchdog.size, &watchdog.sha256)?,
        package_digest("eliot-kernel.exe", kernel.size, &kernel.sha256)?,
        package_digest(
            "eliot-store-surreal.exe",
            store_bridge.size,
            &store_bridge.sha256,
        )?,
        package_digest("surreal.exe", canonical_store.size, &canonical_store.sha256)?,
        package_digest("eliotd.exe", eliotd.size, &eliotd.sha256)?,
        package_digest(
            "eliotd-governor.json",
            governor.len() as u64,
            &governor_sha256,
        )?,
    ];
    let template_digest =
        GenerationPackagePlanner::phase_a_template_content_digest(&template_facts)
            .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let nonce_seed = format!(
        "eliotd:phase-a-template:{}:{}:{}:{}",
        input.transaction_id.as_str(),
        input.installation_epoch.installation.as_str(),
        input.generation.as_str(),
        template_digest.as_str()
    );
    let eliotd_launch_nonce = make_digest(
        format!("eliotd:{}", sha256_hex(nonce_seed.as_bytes())),
        "eliotd launch nonce",
    )?;
    let credential_token = sha256_hex(
        format!(
            "eliot-store-credential:phase-a-template:{}:{}:{}",
            input.installation_epoch.installation.as_str(),
            input.generation.as_str(),
            template_digest.as_str()
        )
        .as_bytes(),
    );
    let store_credential_target = make_digest(
        format!("eliot/store/v1/{}", &credential_token[..32]),
        "Store credential target",
    )?;
    let authority_generation = ResourceGeneration::new(1)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let authority_epoch =
        AuthorityEpoch::new(1).map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let authority_state_fence = StateFence::new(authority_epoch, authority_generation);
    let kernel_arguments = make_args([
        "--work-root".to_owned(),
        roots.kernel_work_root.as_str().to_owned(),
        "--store-bootstrap".to_owned(),
        store_bootstrap_path.as_str().to_owned(),
        "--store-bootstrap-sha256".to_owned(),
        PHASE_B_PENDING_MARKER.to_owned(),
        "--authority-descriptor".to_owned(),
        authority_path.as_str().to_owned(),
        "--authority-descriptor-sha256".to_owned(),
        PHASE_B_PENDING_MARKER.to_owned(),
        "--kernel-artifact-sha256".to_owned(),
        kernel.sha256.clone(),
        "--eliotd-descriptor".to_owned(),
        descriptor_path.as_str().to_owned(),
        "--eliotd-descriptor-sha256".to_owned(),
        "0".repeat(64),
    ])?;
    let store_bridge_arguments = match input.profile {
        InstallationProfile::PortableDev => make_args([
            "--portable-dev-root".to_owned(),
            input.profile_anchor_root.as_str().to_owned(),
            "--config".to_owned(),
            config_path.as_str().to_owned(),
        ])?,
        InstallationProfile::SystemService | InstallationProfile::UserMode => {
            make_args(["--config".to_owned(), config_path.as_str().to_owned()])?
        }
    };
    let canonical_store_arguments = make_args([
        "start".to_owned(),
        "--no-banner".to_owned(),
        "--bind".to_owned(),
        "127.0.0.1:8000".to_owned(),
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
    ])?;
    let descriptor = EliotdLaunchDescriptor {
        wire_id: ELIOTD_LAUNCH_DESCRIPTOR_WIRE_ID.to_owned(),
        wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
        executable: eliotd_path.clone(),
        executable_sha256: eliotd.sha256.clone(),
        arguments: make_args([
            "--config-descriptor".to_owned(),
            governor_path.as_str().to_owned(),
            "--config-descriptor-sha256".to_owned(),
            governor_sha256.clone(),
            "--launch-nonce".to_owned(),
            eliotd_launch_nonce.as_str().to_owned(),
            "--executable-sha256".to_owned(),
            eliotd.sha256.clone(),
        ])?,
        working_directory: roots.kernel_work_root.clone(),
        config_descriptor: governor_path.clone(),
        config_descriptor_sha256: governor_sha256.clone(),
        launch_nonce: eliotd_launch_nonce.clone(),
        authority_epoch,
        generation: authority_generation,
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|error| MaterializeError::Contract(format!("eliotd descriptor: {error}")))?;
    descriptor
        .validate()
        .map_err(|error| MaterializeError::Contract(format!("eliotd descriptor: {error}")))?;
    let descriptor_bytes = serde_json::to_vec(&descriptor).map_err(|error| {
        MaterializeError::Contract(format!("serialize eliotd descriptor: {error}"))
    })?;
    let descriptor_sha256 = sha256_hex(&descriptor_bytes);
    let kernel_arguments = kernel_arguments
        .into_iter()
        .map(|argument| {
            if argument.as_str() == "0".repeat(64) {
                PlatformHandle::new(descriptor_sha256.clone()).map_err(|error| {
                    MaterializeError::Contract(format!("kernel descriptor digest: {error}"))
                })
            } else {
                Ok(argument)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let supervision_lease_scope_id = PlatformHandle::new(format!(
        "eliot-supervision-scope:v1:{}:{}",
        input.installation_epoch.installation, input.generation
    ))
    .map_err(|error| MaterializeError::Contract(format!("supervision scope id: {error}")))?;
    let runtime_launch = RuntimeLaunchDescriptor {
        profile: input.profile,
        portable_root: (input.profile == InstallationProfile::PortableDev)
            .then(|| input.profile_anchor_root.clone()),
        installation_epoch: input.installation_epoch.clone(),
        generation: input.generation.clone(),
        authority_generation,
        authority_state_fence,
        supervision_authority: SupervisionAuthorityBinding::Pending {
            supervision_lease_scope_id,
        },
        authority_descriptor_path: authority_path,
        authority_descriptor_digest: PlatformHandle::new(PHASE_B_PENDING_MARKER)
            .map_err(|error| MaterializeError::Contract(error.to_string()))?,
        runtime_state_roots: roots.clone(),
        kernel_work_root: roots.kernel_work_root.clone(),
        kernel_artifact_digest: make_digest(kernel.sha256.clone(), "kernel digest")?,
        eliotd_executable_path: eliotd_path,
        eliotd_artifact_digest: make_digest(eliotd.sha256.clone(), "eliotd digest")?,
        eliotd_config_path: governor_path,
        eliotd_config_digest: make_digest(governor_sha256.clone(), "governor digest")?,
        eliotd_descriptor_path: descriptor_path,
        eliotd_descriptor_digest: make_digest(descriptor_sha256.clone(), "descriptor digest")?,
        eliotd_launch_nonce: eliotd_launch_nonce.clone(),
        store_config_path: config_path.clone(),
        store_credential_target: store_credential_target.clone(),
        store_bridge_executable_path: store_bridge_path,
        store_bridge_artifact_digest: make_digest(
            store_bridge.sha256.clone(),
            "Store bridge digest",
        )?,
        store_bootstrap_descriptor_path: store_bootstrap_path,
        store_bootstrap_descriptor_digest: PlatformHandle::new(PHASE_B_PENDING_MARKER)
            .map_err(|error| MaterializeError::Contract(error.to_string()))?,
        canonical_store_executable_path: canonical_store_path,
        canonical_store_artifact_digest: make_digest(
            canonical_store.sha256.clone(),
            "Surreal digest",
        )?,
        kernel_arguments,
        store_bridge_arguments,
        canonical_store_arguments,
        host_executable_path: host_path,
        host_artifact_digest: make_digest(host.sha256.clone(), "Host digest")?,
        watchdog_executable_path: watchdog_path,
        watchdog_artifact_digest: make_digest(watchdog.sha256.clone(), "Watchdog digest")?,
        descriptor_digest: PlatformHandle::new("0".repeat(64))
            .map_err(|error| MaterializeError::Contract(error.to_string()))?,
    }
    .with_computed_digest()
    .map_err(|error| MaterializeError::Contract(format!("runtime launch: {error}")))?;
    let credential_ref = runtime_launch.store_credential_target.as_str().to_owned();
    let mut store_config = StoreLaunchConfig {
        store_pipe: format!(r"\\.\pipe\eliot\store-{credential_token}"),
        launch_nonce: format!("store:{credential_token}"),
        expected_client_sid: LOCAL_SERVICE_SID.to_owned(),
        expected_client_session_id: 0,
        approved_artifact_hash: store_bridge.sha256.clone(),
        approved_config_hash: String::new(),
        endpoint: "ws://127.0.0.1:8000/rpc".to_owned(),
        provider_bind_address: "127.0.0.1:8000".to_owned(),
        namespace: "eliot".to_owned(),
        database: "eliot".to_owned(),
        username: "store".to_owned(),
        connect_timeout_ms: 10_000,
        query_timeout_ms: 10_000,
        schema_generation: "1.0.0".to_owned(),
        blob_root: Path::new(roots.store_data_root.as_str())
            .join("blob")
            .to_string_lossy()
            .into_owned(),
        instance_id: format!("store-{}", input.generation.as_str()),
        credential_ref,
        runtime_launch: runtime_launch.clone(),
    };
    store_config.approved_config_hash = launch_config_digest(&store_config)
        .map_err(|error| MaterializeError::Contract(format!("Store config digest: {error}")))?;
    store_config
        .validate_materialized_at(Path::new(runtime_launch.store_config_path.as_str()))
        .map_err(|error| MaterializeError::Contract(format!("Store config: {error}")))?;
    let generation_bytes = serde_json::to_vec(&store_config)
        .map_err(|error| MaterializeError::Contract(format!("serialize Store config: {error}")))?;
    validate_store_config_bytes(&generation_bytes, &runtime_launch)?;
    let json_roles = vec![
        JsonRole {
            name: "generation.json",
            bytes: generation_bytes.clone(),
        },
        JsonRole {
            name: "eliotd-governor.json",
            bytes: governor.clone(),
        },
        JsonRole {
            name: "eliotd.json",
            bytes: descriptor_bytes.clone(),
        },
    ];
    let mut expected = Vec::with_capacity(REQUIRED_ROLES.len());
    for (role, executable) in REQUIRED_ROLES {
        let (size, digest) = if executable {
            let executable = by_name(role)?;
            (executable.size, executable.sha256.clone())
        } else {
            let json = json_roles
                .iter()
                .find(|json| json.name == role)
                .ok_or_else(|| MaterializeError::Invalid(format!("missing JSON role {role}")))?;
            (json.bytes.len() as u64, sha256_hex(&json.bytes))
        };
        expected.push(package_digest(role, size, &digest)?);
    }
    let specs = REQUIRED_ROLES
        .iter()
        .map(|(role, executable)| {
            let expected = expected
                .iter()
                .find(|item| item.relative_path == *role)
                .ok_or_else(|| {
                    MaterializeError::Invalid(format!("expected role missing: {role}"))
                })?;
            PackageFileSpec::new(role, *executable, expected.expected_size)
                .map_err(|error| MaterializeError::Contract(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = PackageManifest::new(input.generation.as_str(), specs)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let evidence_digest =
        GenerationPackagePlanner::artifact_set_evidence_digest(&manifest, &expected)
            .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    Ok(TypedBundle {
        json_roles,
        expected,
        manifest,
        evidence_digest,
    })
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), MaterializeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            MaterializeError::Platform(format!("create {}: {error}", path.display()))
        })?;
    file.write_all(bytes).map_err(|error| {
        MaterializeError::Platform(format!("write {}: {error}", path.display()))
    })?;
    file.sync_all()
        .map_err(|error| MaterializeError::Platform(format!("sync {}: {error}", path.display())))
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<(), MaterializeError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let directory = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| MaterializeError::Platform(format!("open temporary bundle: {error}")))?;
    let metadata = directory
        .metadata()
        .map_err(|error| MaterializeError::Platform(format!("stat temporary bundle: {error}")))?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(MaterializeError::Invalid(
            "temporary bundle is not a regular directory".to_owned(),
        ));
    }
    // Windows does not support flushing a directory handle on every file
    // system and may return ERROR_ACCESS_DENIED even after a valid no-follow
    // directory open. Every role file is already flushed before this point;
    // retain the directory validation and treat the platform flush as best
    // effort, matching the platform's existing atomic staging helper.
    let _ = directory.sync_all();
    Ok(())
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> Result<(), MaterializeError> {
    let directory = fs::File::open(path)
        .map_err(|error| MaterializeError::Platform(format!("open temporary bundle: {error}")))?;
    directory
        .sync_all()
        .map_err(|error| MaterializeError::Platform(format!("sync temporary bundle: {error}")))
}

fn role_bytes<'a>(
    role: &str,
    executables: &'a [ValidatedExecutable],
    json_roles: &'a [JsonRole],
) -> Result<&'a [u8], MaterializeError> {
    if let Some(executable) = executables.iter().find(|item| item.name == role) {
        return Ok(executable.bytes.as_slice());
    }
    json_roles
        .iter()
        .find(|item| item.name == role)
        .map(|item| item.bytes.as_slice())
        .ok_or_else(|| MaterializeError::Invalid(format!("missing source role {role}")))
}

fn validate_published_observation(
    bundle: &TrustedSourceBundle,
    manifest: &PackageManifest,
    expected: &[PackageArtifactDigest],
) -> Result<BTreeMap<String, eliot_platform_windows::PackageSourceFileObservation>, MaterializeError>
{
    let observed = bundle.observe().map_err(|error| {
        MaterializeError::Platform(format!("observe published bundle: {error}"))
    })?;
    if observed.files.len() != REQUIRED_ROLES.len() {
        return Err(MaterializeError::Invalid(
            "published source bundle has an incomplete role inventory".to_owned(),
        ));
    }
    let mut by_role = BTreeMap::new();
    for (role, executable) in REQUIRED_ROLES {
        let item = observed
            .files
            .iter()
            .find(|item| item.relative_path == role)
            .ok_or_else(|| MaterializeError::Invalid(format!("published role missing: {role}")))?;
        let expected_item = expected
            .iter()
            .find(|item| item.relative_path == role)
            .ok_or_else(|| MaterializeError::Invalid(format!("expected role missing: {role}")))?;
        let spec = manifest
            .files
            .iter()
            .find(|spec| spec.relative_path == role)
            .ok_or_else(|| MaterializeError::Invalid(format!("manifest role missing: {role}")))?;
        if spec.executable != executable
            || item.size != expected_item.expected_size
            || item.sha256 != expected_item.sha256.as_str()
            || (executable && item.pe.is_none())
            || (!executable && item.pe.is_some())
            || item.identity.volume_serial_number == 0
            || item.identity.file_index == 0
        {
            return Err(MaterializeError::Invalid(format!(
                "published role readback mismatch: {role}"
            )));
        }
        by_role.insert(role.to_owned(), item.clone());
    }
    Ok(by_role)
}

#[allow(
    clippy::too_many_lines,
    reason = "publication keeps validation, immutable writes, readback and receipt binding together"
)]
fn materialize_with_executables(
    input: &CanarySourceBundleMaterializeInput,
    executables: &[ValidatedExecutable],
) -> Result<CanarySourceBundleMaterializeOutcome, MaterializeError> {
    validate_role_inventory(&REQUIRED_ROLES)?;
    validate_absolute(&input.output_bundle, "output_bundle")?;
    validate_absolute(
        Path::new(input.profile_anchor_root.as_str()),
        "profile_anchor_root",
    )?;
    validate_absolute(Path::new(input.staging_root.as_str()), "staging_root")?;
    validate_package_relative_path(Path::new(input.generation.as_str()))
        .map_err(|error| MaterializeError::Invalid(format!("generation: {error}")))?;
    if input.transaction_id.as_str().trim().is_empty()
        || input.transaction_id.as_str().chars().any(char::is_control)
    {
        return Err(MaterializeError::Invalid(
            "transaction_id must be non-blank and free of controls".to_owned(),
        ));
    }
    input
        .installation_epoch
        .validate()
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    if executables.len() != 6 {
        return Err(MaterializeError::Invalid(
            "exactly six validated executables are required".to_owned(),
        ));
    }

    let typed = build_typed_bundle(input, executables)?;
    let publication = OwnedDirectoryPublication::create(&input.output_bundle)
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    let temp = publication.temporary_path().to_path_buf();
    let mut source_identities = BTreeMap::<String, FileIdentity>::new();
    for (role, executable) in REQUIRED_ROLES {
        let bytes = role_bytes(role, executables, &typed.json_roles)?;
        let destination = temp.join(role);
        write_create_new(&destination, bytes)?;
        let identity =
            eliot_platform_windows::file_identity_for_path(&destination).map_err(|error| {
                MaterializeError::Platform(format!("read source identity {role}: {error}"))
            })?;
        if identity.volume_serial_number == 0 || identity.file_index == 0 {
            return Err(MaterializeError::Invalid(format!(
                "source identity is zero: {role}"
            )));
        }
        source_identities.insert(role.to_owned(), identity);
        if executable {
            let expected = typed
                .expected
                .iter()
                .find(|item| item.relative_path == role)
                .ok_or_else(|| {
                    MaterializeError::Invalid(format!("expected role missing: {role}"))
                })?;
            if bytes.len() as u64 != expected.expected_size
                || sha256_hex(bytes) != expected.sha256.as_str()
            {
                return Err(MaterializeError::Invalid(format!(
                    "validated executable bytes changed before publication: {role}"
                )));
            }
        }
    }
    sync_directory(&temp)?;

    let precommit_bundle = TrustedSourceBundle::open(&temp).map_err(|error| {
        MaterializeError::Platform(format!("open precommit source bundle: {error}"))
    })?;
    let precommit_observed =
        validate_published_observation(&precommit_bundle, &typed.manifest, &typed.expected)?;
    let precommit_directory_identity = precommit_bundle.identity();
    if precommit_directory_identity != publication.temporary_identity()
        || precommit_directory_identity.volume_serial_number == 0
        || precommit_directory_identity.file_index == 0
    {
        return Err(MaterializeError::Invalid(
            "precommit temporary bundle identity changed".to_owned(),
        ));
    }
    let evidence =
        GenerationPackagePlanner::artifact_set_evidence_digest(&typed.manifest, &typed.expected)
            .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    if evidence != typed.evidence_digest {
        return Err(MaterializeError::Invalid(
            "artifact evidence digest changed before commit".to_owned(),
        ));
    }

    let mut precommit_files = Vec::with_capacity(REQUIRED_ROLES.len());
    for (role, executable) in REQUIRED_ROLES {
        let expected = typed
            .expected
            .iter()
            .find(|item| item.relative_path == role)
            .ok_or_else(|| MaterializeError::Invalid(format!("expected role missing: {role}")))?;
        let actual = precommit_observed
            .get(role)
            .ok_or_else(|| MaterializeError::Invalid(format!("precommit role missing: {role}")))?;
        let created_identity = *source_identities.get(role).ok_or_else(|| {
            MaterializeError::Invalid(format!("created identity missing: {role}"))
        })?;
        if created_identity != actual.identity {
            return Err(MaterializeError::Invalid(format!(
                "created role identity changed before commit: {role}"
            )));
        }
        let (source_identity, pe, authenticode) = if executable {
            let source = executables
                .iter()
                .find(|item| item.name == role)
                .ok_or_else(|| MaterializeError::Invalid(format!("executable missing: {role}")))?;
            (
                source.identity,
                Some(source.pe.clone()),
                Some(source.authenticode.clone()),
            )
        } else {
            (created_identity, None, None)
        };
        precommit_files.push(MaterializedRolePrecommitReceipt {
            relative_path: role.to_owned(),
            executable,
            size: expected.expected_size,
            sha256: expected.sha256.as_str().to_owned(),
            source_identity,
            temporary_identity: actual.identity,
            pe,
            authenticode,
        });
    }
    drop(precommit_bundle);

    let directory_publication = publication
        .publish(precommit_directory_identity)
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    let destination_path = match &directory_publication {
        DirectoryPublicationOutcome::Published(receipt) => receipt.destination_path.clone(),
        DirectoryPublicationOutcome::CommittedUnknown(receipt) => receipt.destination_path.clone(),
    };
    let DirectoryPublicationOutcome::Published(publication_receipt) = &directory_publication else {
        return Ok(CanarySourceBundleMaterializeOutcome::CommittedUnknown(
            CanarySourceBundleReconciliation {
                bundle_path: destination_path,
                generation: input.generation.as_str().to_owned(),
                evidence_digest: typed.evidence_digest.as_str().to_owned(),
                precommit_files,
                directory_publication,
                reason: CanarySourceBundleReconciliationReason::DirectoryPublicationUnknown,
                diagnostic: "directory move committed without an exact post-commit receipt"
                    .to_owned(),
            },
        ));
    };

    let postcommit = (|| {
        let bundle = TrustedSourceBundle::open(Path::new(&publication_receipt.destination_path))
            .map_err(|error| {
                MaterializeError::Platform(format!("open published bundle: {error}"))
            })?;
        if bundle.identity() != publication_receipt.destination_identity
            || publication_receipt.source_identity != publication_receipt.destination_identity
        {
            return Err(MaterializeError::Invalid(
                "published bundle directory identity mismatch".to_owned(),
            ));
        }
        let observed = validate_published_observation(&bundle, &typed.manifest, &typed.expected)?;
        let receipt_evidence = GenerationPackagePlanner::artifact_set_evidence_digest(
            &typed.manifest,
            &typed.expected,
        )
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
        if receipt_evidence != typed.evidence_digest {
            return Err(MaterializeError::Invalid(
                "artifact evidence digest changed before receipt".to_owned(),
            ));
        }
        let mut files = Vec::with_capacity(REQUIRED_ROLES.len());
        for prepared in &precommit_files {
            let actual = observed.get(&prepared.relative_path).ok_or_else(|| {
                MaterializeError::Invalid(format!(
                    "published role missing: {}",
                    prepared.relative_path
                ))
            })?;
            if actual.identity != prepared.temporary_identity {
                return Err(MaterializeError::Invalid(format!(
                    "published role identity changed: {}",
                    prepared.relative_path
                )));
            }
            files.push(MaterializedRoleReceipt {
                relative_path: prepared.relative_path.clone(),
                executable: prepared.executable,
                size: prepared.size,
                sha256: prepared.sha256.clone(),
                source_identity: prepared.source_identity,
                destination_identity: actual.identity,
                pe: prepared.pe.clone(),
                authenticode: prepared.authenticode.clone(),
            });
        }
        Ok(CanarySourceBundleReceipt {
            bundle_path: publication_receipt.destination_path.clone(),
            generation: input.generation.as_str().to_owned(),
            evidence_digest: typed.evidence_digest.as_str().to_owned(),
            files,
            source_identity: publication_receipt.source_identity,
            directory_publication: publication_receipt.clone(),
        })
    })();
    match postcommit {
        Ok(receipt) => Ok(CanarySourceBundleMaterializeOutcome::Published(receipt)),
        Err(error) => Ok(CanarySourceBundleMaterializeOutcome::CommittedUnknown(
            CanarySourceBundleReconciliation {
                bundle_path: destination_path,
                generation: input.generation.as_str().to_owned(),
                evidence_digest: typed.evidence_digest.as_str().to_owned(),
                precommit_files,
                directory_publication,
                reason: CanarySourceBundleReconciliationReason::PostCommitBundleReadbackRejected,
                diagnostic: error.to_string(),
            },
        )),
    }
}

/// Materialize one exact nine-role Phase-A source bundle.
pub fn materialize_canary_source_bundle(
    input: &CanarySourceBundleMaterializeInput,
) -> Result<CanarySourceBundleMaterializeOutcome, InstallationError> {
    let executable_inputs = [
        (input.eliot_host_exe.clone(), "eliot-host.exe"),
        (input.eliot_watchdog_exe.clone(), "eliot-watchdog.exe"),
        (input.eliot_kernel_exe.clone(), "eliot-kernel.exe"),
        (
            input.eliot_store_surreal_exe.clone(),
            "eliot-store-surreal.exe",
        ),
        (input.surreal_exe.clone(), "surreal.exe"),
        (input.eliotd_exe.clone(), "eliotd.exe"),
    ];
    let executables = executable_inputs
        .into_iter()
        .map(|(path, role)| validate_executable(&path, role).map_err(to_installation_error))
        .collect::<Result<Vec<_>, _>>()?;
    materialize_with_executables(input, &executables).map_err(to_installation_error)
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    use eliot_installation::GenerationPackagePlanInput;
    use tempfile::TempDir;

    #[cfg(windows)]
    use eliot_platform_windows::UserOwnedRootLease;

    fn handle(value: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(value.into()).unwrap()
    }

    fn minimal_pe() -> Vec<u8> {
        let pe_offset = 0x80_usize;
        let optional_size = 0xf0_usize;
        let section_end = pe_offset + 4 + 20 + optional_size + 40;
        let mut bytes = vec![0_u8; section_end];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_offset + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&2_u16.to_le_bytes());
        bytes[coff + 20..coff + 22].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes
    }

    #[cfg(windows)]
    fn fake_executables() -> Vec<ValidatedExecutable> {
        [
            "eliot-host.exe",
            "eliot-watchdog.exe",
            "eliot-kernel.exe",
            "eliot-store-surreal.exe",
            "surreal.exe",
            "eliotd.exe",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            let mut bytes = minimal_pe();
            bytes.extend_from_slice(name.as_bytes());
            let sha256 = sha256_hex(&bytes);
            let pe = parse_pe_coff(&bytes).unwrap();
            ValidatedExecutable {
                name,
                size: bytes.len() as u64,
                bytes,
                sha256,
                identity: FileIdentity {
                    volume_serial_number: 1,
                    file_index: (index + 1) as u64,
                },
                pe,
                authenticode: AuthenticodeEvidence {
                    verdict: eliot_platform_windows::AuthenticodeVerdict::Valid,
                    signer_certificate_sha256: None,
                    signer_subject: None,
                    signer_not_before_unix_seconds: None,
                    signer_not_after_unix_seconds: None,
                    verification_time_unix_seconds: None,
                    countersigner_certificate_sha256: None,
                    trust_status: 0,
                },
            }
        })
        .collect()
    }

    #[cfg(windows)]
    fn test_input(
        source_parent: &TempDir,
        anchor: &TempDir,
        staging: &TempDir,
    ) -> CanarySourceBundleMaterializeInput {
        // The production path intentionally requires the read-only lease to
        // observe an already-provisioned protected portable root.  Provision
        // this disposable fixture with the existing installer helper instead
        // of weakening that ACL contract for tests.
        UserOwnedRootLease::open_existing(anchor.path()).unwrap();
        CanarySourceBundleMaterializeInput {
            eliot_host_exe: PathBuf::new(),
            eliot_watchdog_exe: PathBuf::new(),
            eliot_kernel_exe: PathBuf::new(),
            eliot_store_surreal_exe: PathBuf::new(),
            surreal_exe: PathBuf::new(),
            eliotd_exe: PathBuf::new(),
            output_bundle: source_parent.path().join("bundle"),
            generation: handle("generation-test"),
            installation_epoch: InstallationEpoch {
                installation: handle("installation-test"),
                lineage_id: handle("lineage-test"),
                sequence: 1,
            },
            profile: InstallationProfile::PortableDev,
            profile_anchor_root: handle(anchor.path().to_string_lossy().into_owned()),
            installation_key: None,
            transaction_id: handle("transaction:test"),
            staging_root: handle(
                staging
                    .path()
                    .join("staging")
                    .to_string_lossy()
                    .into_owned(),
            ),
        }
    }

    #[cfg(windows)]
    fn materialized_fixture() -> (
        TempDir,
        TempDir,
        TempDir,
        CanarySourceBundleMaterializeInput,
        CanarySourceBundleReceipt,
    ) {
        let source_parent = TempDir::new().unwrap();
        let anchor = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();
        let input = test_input(&source_parent, &anchor, &staging);
        let outcome = materialize_with_executables(&input, &fake_executables()).unwrap();
        let CanarySourceBundleMaterializeOutcome::Published(receipt) = outcome else {
            panic!("exact materializer publication unexpectedly requires reconciliation");
        };
        (source_parent, anchor, staging, input, receipt)
    }

    #[cfg(windows)]
    fn bound_plan_input(
        input: &CanarySourceBundleMaterializeInput,
        output_bundle: &Path,
    ) -> GenerationPackagePlanInput {
        GenerationPackagePlanInput {
            transaction_id: input.transaction_id.clone(),
            installation_epoch: input.installation_epoch.clone(),
            profile: input.profile,
            profile_anchor_root: input.profile_anchor_root.clone(),
            installation_key: None,
            generation: input.generation.clone(),
            source_root: handle(output_bundle.to_string_lossy().into_owned()),
            staging_root: input.staging_root.clone(),
            minimum_store_available_bytes: 1,
            recovery_command: handle("eliot recover --transaction-id transaction:test"),
        }
    }

    #[cfg(windows)]
    fn assert_publication_binding_rejects(
        mutate: impl FnOnce(&mut SourceBundlePublicationBinding, &Path),
    ) {
        let (_source_parent, _anchor, _staging, input, receipt) = materialized_fixture();
        let output_bundle = PathBuf::from(&receipt.bundle_path);
        let mut binding = receipt.planner_binding().unwrap();
        mutate(&mut binding, &output_bundle);
        let result = GenerationPackagePlanner::plan_with_source_publication_binding(
            bound_plan_input(&input, &output_bundle),
            binding.source_identity,
            binding.files,
            binding.evidence_digest,
        );
        assert!(result.is_err());
    }

    #[test]
    fn phase_b_roles_and_reordered_roles_are_rejected() {
        let mut reordered = REQUIRED_ROLES;
        reordered.swap(0, 1);
        assert!(validate_role_inventory(&reordered).is_err());
        let mut extra = REQUIRED_ROLES.to_vec();
        extra.push(("authority.json", false));
        assert!(validate_role_inventory(&extra).is_err());
        let mut substituted = REQUIRED_ROLES;
        substituted[6] = ("authority.json", false);
        assert!(validate_role_inventory(&substituted).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn materializer_output_matches_real_planner_launch_template() {
        let source_parent = TempDir::new().unwrap();
        let anchor = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();
        let input = test_input(&source_parent, &anchor, &staging);
        let outcome = materialize_with_executables(&input, &fake_executables()).unwrap();
        let CanarySourceBundleMaterializeOutcome::Published(receipt) = outcome else {
            panic!("exact materializer publication unexpectedly requires reconciliation");
        };
        assert_eq!(receipt.files.len(), 9);
        assert_eq!(
            receipt.directory_publication.source_identity,
            receipt.directory_publication.destination_identity
        );
        let output_bundle = PathBuf::from(&receipt.bundle_path);
        let binding = receipt.planner_binding().unwrap();
        let transaction = GenerationPackagePlanner::plan_with_source_publication_binding(
            GenerationPackagePlanInput {
                transaction_id: input.transaction_id.clone(),
                installation_epoch: input.installation_epoch.clone(),
                profile: input.profile,
                profile_anchor_root: input.profile_anchor_root.clone(),
                installation_key: None,
                generation: input.generation.clone(),
                source_root: handle(output_bundle.to_string_lossy().into_owned()),
                staging_root: input.staging_root.clone(),
                minimum_store_available_bytes: 1,
                recovery_command: handle("eliot recover --transaction-id transaction:test"),
            },
            binding.source_identity,
            binding.files,
            binding.evidence_digest,
        )
        .expect("materialized bundle must feed the real planner");
        let config_bytes = fs::read(output_bundle.join("generation.json")).unwrap();
        let config: StoreLaunchConfig = serde_json::from_slice(&config_bytes).unwrap();
        assert_eq!(
            config.expected_client_sid, LOCAL_SERVICE_SID,
            "Store peer binding must match the LocalService Host/Kernel contour"
        );
        let governor_bytes = fs::read(output_bundle.join("eliotd-governor.json")).unwrap();
        let governor: GovernorLaunchConfig = serde_json::from_slice(&governor_bytes).unwrap();
        assert_eq!(
            governor.kernel.principal, LOCAL_SERVICE_SID,
            "Governor Kernel principal must match the LocalService child-token contour"
        );
        config
            .validate_materialized_at(Path::new(
                transaction
                    .candidate_manifest
                    .runtime_launch
                    .store_config_path
                    .as_str(),
            ))
            .unwrap();
        assert_eq!(
            config.runtime_launch, transaction.candidate_manifest.runtime_launch,
            "Host's exact Store template equality seam must pass"
        );
        assert_eq!(
            config.credential_ref,
            transaction
                .candidate_manifest
                .runtime_launch
                .store_credential_target
                .as_str()
        );
        assert!(!output_bundle.join("authority.json").exists());
        assert!(!output_bundle.join("store-bootstrap.json").exists());
    }

    #[cfg(windows)]
    #[test]
    fn publication_binding_rejects_root_identity_mutation() {
        assert_publication_binding_rejects(|binding, _| {
            binding.source_identity.file_index =
                binding.source_identity.file_index.saturating_add(1);
        });
    }

    #[cfg(windows)]
    #[test]
    fn publication_binding_rejects_pe_mutation() {
        assert_publication_binding_rejects(|_, bundle| {
            let path = bundle.join("eliot-host.exe");
            let mut bytes = fs::read(&path).unwrap();
            bytes.push(0xa5);
            fs::write(path, bytes).unwrap();
        });
    }

    #[cfg(windows)]
    #[test]
    fn publication_binding_rejects_json_mutation() {
        assert_publication_binding_rejects(|_, bundle| {
            let path = bundle.join("generation.json");
            let mut bytes = fs::read(&path).unwrap();
            bytes.push(b' ');
            fs::write(path, bytes).unwrap();
        });
    }

    #[cfg(windows)]
    #[test]
    fn publication_binding_rejects_missing_or_extra_role() {
        assert_publication_binding_rejects(|_, bundle| {
            fs::remove_file(bundle.join("generation.json")).unwrap();
        });
        assert_publication_binding_rejects(|_, bundle| {
            fs::write(bundle.join("unexpected.txt"), b"unexpected").unwrap();
        });
    }

    #[cfg(windows)]
    #[test]
    fn publication_binding_rejects_evidence_mutation() {
        assert_publication_binding_rejects(|binding, _| {
            binding.evidence_digest = handle("0".repeat(64));
        });
    }

    #[cfg(windows)]
    #[test]
    fn typed_json_substitution_and_tamper_are_rejected() {
        let source_parent = TempDir::new().unwrap();
        let anchor = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();
        let input = test_input(&source_parent, &anchor, &staging);
        let typed = build_typed_bundle(&input, &fake_executables()).unwrap();
        let generation = typed
            .json_roles
            .iter()
            .find(|item| item.name == "generation.json")
            .unwrap();
        let expected_config: StoreLaunchConfig = serde_json::from_slice(&generation.bytes).unwrap();
        let expected_launch = expected_config.runtime_launch.clone();
        validate_store_config_bytes(&generation.bytes, &expected_launch).unwrap();

        let mut substituted: StoreLaunchConfig = serde_json::from_slice(&generation.bytes).unwrap();
        substituted.runtime_launch.generation = handle("substituted-generation");
        let substituted_bytes = serde_json::to_vec(&substituted).unwrap();
        assert!(validate_store_config_bytes(&substituted_bytes, &expected_launch).is_err());

        let mut tampered = generation.bytes.clone();
        let index = tampered
            .windows(8)
            .position(|window| window == b"eliot/st")
            .unwrap_or(0);
        tampered[index] = tampered[index].wrapping_add(1);
        assert!(validate_store_config_bytes(&tampered, &expected_launch).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn bad_signature_is_rejected_before_publication() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("eliot-host.exe");
        let mut bytes = minimal_pe();
        bytes.extend_from_slice(b"unsigned");
        fs::write(&path, bytes).unwrap();
        assert!(validate_executable(&path, "eliot-host.exe").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn output_failure_does_not_replace_existing_bundle() {
        let source_parent = TempDir::new().unwrap();
        let anchor = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();
        let mut input = test_input(&source_parent, &anchor, &staging);
        fs::create_dir(input.output_bundle.clone()).unwrap();
        fs::write(input.output_bundle.join("owner.txt"), b"existing").unwrap();
        let error = materialize_with_executables(&input, &fake_executables()).unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(
            fs::read(input.output_bundle.join("owner.txt")).unwrap(),
            b"existing"
        );
        input.output_bundle = source_parent.path().join("different-bundle");
        assert!(!input.output_bundle.exists());
    }
}
