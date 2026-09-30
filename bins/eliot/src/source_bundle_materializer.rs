#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use eliot_contracts::{EpochId, EpochLineageId};
use eliot_governor::{GovernorLaunchConfig, KernelGenerationExpectation};
use eliot_installation::{
    AgentBridgeSourceMaterializationFactory, AgentBridgeSourceMaterializationPlan,
    GenerationPackagePlanner, InstallationEpoch, InstallationError, InstallationProfile,
    InstallationRecoveryStage, LOCAL_SERVICE_SID, PHASE_B_PENDING_MARKER, PackageArtifactDigest,
    PlatformHandle, ProfileSelectionInput, ProfileSelectionResolution,
    RedbInstallationTransactionStore, ResourceGeneration, RuntimeLaunchDescriptor,
    SOURCE_BUNDLE_PUBLICATION_JOURNAL_WIRE_VERSION, SourceBundlePublicationJournal,
    SourceBundlePublicationJournalState, SourceBundlePublicationRole, StateFence,
    SupervisionAuthorityBinding, agent_bridge_source_plan_from_observed_kernel,
    provider_bootstrap_credential_target_for_store_target, source_bundle_publication_operation_id,
};
use eliot_kernel_service::EliotdLaunchDescriptor;
use eliot_platform_windows::{
    AuthenticodeEvidence, AuthenticodeVerifier, DirectoryPublicationOutcome,
    DirectoryPublicationReceipt, FileIdentity, OwnedDirectoryPublication, PackageFileSpec,
    PackageManifest, PeCoffEvidence, TrustedSourceBundle, WindowsAuthenticodeVerifier,
    canonical_windows_path, open_no_follow_directory, parse_pe_coff, resolve_account_sid,
    validate_package_relative_path,
};
use eliot_runtime_contracts::{
    RUNTIME_LIVE_STORE_BIND, RUNTIME_LIVE_STORE_ENDPOINT, RUNTIME_LIVE_STORE_NAMESPACE,
    RuntimeLiveStoreIdentity,
};
use eliot_store_surreal::{StoreLaunchConfig, launch_config_digest};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_EXECUTABLE_BYTES: usize = 512 * 1024 * 1024;
const ELIOTD_LAUNCH_DESCRIPTOR_WIRE_ID: &str = "eliot.kernel.eliotd-launch";
/// Lineage used to bind the materializer-pinned genesis scalar to its canonical
/// [`EpochId`] tuple. The genesis wire remains sequence one; this binary
/// performs only the mechanical tuple binding and never mints authority.
const MATERIALIZER_EPOCH_LINEAGE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

fn materializer_genesis_epoch() -> Result<EpochId, MaterializeError> {
    let lineage = EpochLineageId::new(MATERIALIZER_EPOCH_LINEAGE_ID)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let sequence = std::num::NonZeroU64::new(1).ok_or_else(|| {
        MaterializeError::Contract("materializer genesis epoch must be non-zero".to_owned())
    })?;
    EpochId::new(lineage, sequence).map_err(|error| MaterializeError::Contract(error.to_string()))
}

/// The only source roles admitted to Phase A.
///
/// `authority.json` and `store-bootstrap.json` are intentionally absent. They
/// are Host-owned Phase-B material and can never be supplied by this command.
pub const REQUIRED_ROLES: [(&str, bool); 15] = [
    ("eliot-host.exe", true),
    ("eliot-watchdog.exe", true),
    ("eliot-kernel.exe", true),
    ("eliot-store-surreal.exe", true),
    ("surreal.exe", true),
    ("eliotd.exe", true),
    ("eliot-doctor.exe", true),
    ("eliot-testd.exe", true),
    ("eliot-native-worker.exe", true),
    ("eliot-wasm-host.exe", true),
    ("eliot-user-broker.exe", true),
    ("eliot-notify.exe", true),
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
    /// Release `eliot-doctor.exe` path.
    pub eliot_doctor_exe: PathBuf,
    /// Release `eliot-testd.exe` path.
    pub eliot_testd_exe: PathBuf,
    /// Release `eliot-native-worker.exe` path.
    pub eliot_native_worker_exe: PathBuf,
    /// Release `eliot-wasm-host.exe` path.
    pub eliot_wasm_host_exe: PathBuf,
    /// Release per-user `eliot-user-broker.exe` path.
    pub eliot_user_broker_exe: PathBuf,
    /// Release `eliot-notify.exe` path (per-user one-shot adapter, I1.3).
    pub eliot_notify_exe: PathBuf,
    /// Optional explicit external agent-bridge executable source.
    pub agent_bridge_exe: Option<PathBuf>,
    /// Optional account name resolved by Windows to the approved stable SID.
    pub agent_bridge_account: Option<String>,
    /// Absent absolute directory to create exactly once.
    pub output_bundle: PathBuf,
    /// Exact redb store that owns the publication intent/outcome journal.
    pub store_path: PathBuf,
    /// Canonical relative generation identity.
    pub generation: PlatformHandle,
    /// Installation lineage used by the typed launch contracts.
    pub installation_epoch: InstallationEpoch,
    /// Complete explicit I3.1 selection, including OS-proved anchors, versioned
    /// component identity, retained runtime anchor, and protected write paths.
    pub profile_selection: ProfileSelectionInput,
    /// Stable transaction identity used by the planner's launch-template
    /// derivation.
    pub transaction_id: PlatformHandle,
    /// Explicit destination staging root used by the bound generation planner.
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
    /// Exact I3.1 root binding retained by publication and Generate.
    pub profile_governed_roots: eliot_installation::InstallationRoots,
    /// Full fifteen-role canonical artifact evidence digest.
    pub evidence_digest: String,
    /// Exact role inventory, identities and byte facts.
    pub files: Vec<MaterializedRoleReceipt>,
    /// Identity of the published bundle directory.
    pub source_identity: FileIdentity,
    /// Exact directory create-new publication receipt.
    pub directory_publication: DirectoryPublicationReceipt,
    /// Canonical path of the profile anchor selected before source writes.
    pub selected_profile_anchor_path: String,
    /// Object identity of the retained profile anchor handle selected before
    /// source writes.
    pub selected_profile_anchor_identity: FileIdentity,
}

/// The non-wire proof handed directly to the generation planner.  It carries
/// the exact published root identity, the selected profile-anchor object,
/// ordered fifteen-role byte facts, and full evidence digest; the planner
/// independently reopens and observes the source path before accepting these
/// facts.
#[derive(Clone, Debug)]
pub(crate) struct SourceBundlePublicationBinding {
    pub source_identity: FileIdentity,
    pub files: Vec<PackageArtifactDigest>,
    pub evidence_digest: PlatformHandle,
    pub profile_governed_roots: eliot_installation::InstallationRoots,
    pub retained_profile_anchor: eliot_installation::RetainedProfileAnchor,
}

impl CanarySourceBundleReceipt {
    pub(crate) fn planner_binding(
        &self,
    ) -> Result<SourceBundlePublicationBinding, MaterializeError> {
        if self.files.len() != REQUIRED_ROLES.len()
            || self.source_identity != self.directory_publication.source_identity
            || self.source_identity != self.directory_publication.destination_identity
            || self.selected_profile_anchor_identity.volume_serial_number == 0
            || self.selected_profile_anchor_identity.file_index == 0
            || !eliot_platform_windows::windows_paths_equal(
                Path::new(&self.selected_profile_anchor_path),
                Path::new(
                    self.profile_governed_roots
                        .runtime_state_roots
                        .profile_anchor_root
                        .as_str(),
                ),
            )
        {
            return Err(MaterializeError::Invalid(
                "published source receipt is not an exact fifteen-role directory publication"
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
        let canonical_path = PlatformHandle::new(self.selected_profile_anchor_path.clone())
            .map_err(|error| {
                MaterializeError::Contract(format!("selected profile anchor path: {error}"))
            })?;
        Ok(SourceBundlePublicationBinding {
            source_identity: self.source_identity,
            files,
            evidence_digest,
            profile_governed_roots: self.profile_governed_roots.clone(),
            retained_profile_anchor: eliot_installation::RetainedProfileAnchor {
                canonical_path,
                identity: self.selected_profile_anchor_identity,
            },
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
    /// Directory publication was exact, but the complete fifteen-role
    /// post-commit source-bundle readback was rejected.
    #[allow(
        dead_code,
        reason = "retained wire value for older reconciliation receipts"
    )]
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
    /// Exact I3.1 root binding retained by the durable publication journal.
    pub profile_governed_roots: eliot_installation::InstallationRoots,
    /// Full fifteen-role canonical artifact evidence digest.
    pub evidence_digest: String,
    /// Complete role facts measured before the atomic commit.
    pub precommit_files: Vec<MaterializedRolePrecommitReceipt>,
    /// Exact platform result, including source and parent identities.
    pub directory_publication: DirectoryPublicationOutcome,
    /// Why normal receipt promotion and Generate were withheld.
    pub reason: CanarySourceBundleReconciliationReason,
    /// Non-authoritative bounded diagnostic for operator triage.
    pub diagnostic: String,
    /// Canonical path of the profile anchor selected before source writes.
    pub selected_profile_anchor_path: String,
    /// Object identity of the retained profile anchor handle selected before
    /// source writes.
    pub selected_profile_anchor_identity: FileIdentity,
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
    #[error(
        "materialize recovery required for {operation} at {stage:?} ({source_context}); cleanup={cleanup:?}"
    )]
    RecoveryRequired {
        operation: String,
        stage: InstallationRecoveryStage,
        source_context: String,
        cleanup: Option<String>,
    },
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
            MaterializeError::RecoveryRequired {
                operation,
                stage,
                source_context,
                cleanup,
            } => Self::RecoveryRequired {
                operation,
                stage,
                source_context,
                cleanup,
            },
        }
    }
}

/// Evidence retained from the profile-anchor object chosen before source
/// materialization. The caller keeps `handle` alive until the complete
/// staging/reconcile/publish operation returns.
#[derive(Clone, Debug)]
struct SelectedProfileAnchor<'a> {
    canonical_path: PathBuf,
    identity: FileIdentity,
    handle: &'a File,
}

impl<'a> SelectedProfileAnchor<'a> {
    fn retain(
        input: &CanarySourceBundleMaterializeInput,
        selection: &ProfileSelectionResolution,
        handle: &'a File,
        expected_identity: FileIdentity,
    ) -> Result<Self, MaterializeError> {
        if expected_identity.volume_serial_number == 0 || expected_identity.file_index == 0 {
            return Err(MaterializeError::Invalid(
                "selected profile anchor identity is zero".to_owned(),
            ));
        }
        let handle_identity = eliot_platform_windows::file_identity_for_open_handle(handle)
            .map_err(|error| MaterializeError::Platform(error.to_string()))?;
        if handle_identity != expected_identity {
            return Err(MaterializeError::Invalid(
                "retained profile anchor handle differs from the selected identity".to_owned(),
            ));
        }

        let input_path = canonical_windows_path(Path::new(
            input.profile_selection.profile_anchor_root.as_str(),
        ))
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
        let resolved_path = canonical_windows_path(Path::new(
            selection
                .roots
                .runtime_state_roots
                .profile_anchor_root
                .as_str(),
        ))
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
        if !eliot_platform_windows::windows_paths_equal(&input_path, &resolved_path) {
            return Err(MaterializeError::Invalid(
                "resolved profile anchor path differs from the selected input".to_owned(),
            ));
        }
        let (path_identity, _path_handle) = open_no_follow_directory(&input_path)
            .map_err(|error| MaterializeError::Platform(error.to_string()))?;
        if path_identity != expected_identity {
            return Err(MaterializeError::Invalid(
                "selected profile anchor path names a different directory object".to_owned(),
            ));
        }

        let anchor = Self {
            canonical_path: input_path,
            identity: expected_identity,
            handle,
        };
        anchor.revalidate()?;
        Ok(anchor)
    }

    /// Rechecks the original open object and its selected canonical path at a
    /// source mutation boundary. The no-follow path probe rejects a replaced
    /// root while the retained handle proves which object was originally
    /// selected.
    fn revalidate(&self) -> Result<(), MaterializeError> {
        let handle_identity = eliot_platform_windows::file_identity_for_open_handle(self.handle)
            .map_err(|error| MaterializeError::Platform(error.to_string()))?;
        if handle_identity != self.identity {
            return Err(MaterializeError::Invalid(
                "retained profile anchor object identity changed".to_owned(),
            ));
        }
        let current_path = canonical_windows_path(&self.canonical_path)
            .map_err(|error| MaterializeError::Platform(error.to_string()))?;
        if !eliot_platform_windows::windows_paths_equal(&self.canonical_path, &current_path) {
            return Err(MaterializeError::Invalid(
                "selected profile anchor path changed during materialization".to_owned(),
            ));
        }
        let (path_identity, _path_handle) = open_no_follow_directory(&self.canonical_path)
            .map_err(|error| MaterializeError::Platform(error.to_string()))?;
        if path_identity != self.identity {
            return Err(MaterializeError::Invalid(
                "selected profile anchor path now names another directory object".to_owned(),
            ));
        }
        Ok(())
    }

    fn path_string(&self) -> String {
        self.canonical_path.to_string_lossy().into_owned()
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
    profile_governed_roots: eliot_installation::InstallationRoots,
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
            "Phase-A source bundle must contain exactly fifteen roles".to_owned(),
        ));
    }
    for (actual, expected) in roles.iter().zip(REQUIRED_ROLES) {
        if actual != &expected {
            return Err(MaterializeError::Invalid(format!(
                "role inventory must be the exact ordered fifteen-role Phase-A set; got {}",
                actual.0
            )));
        }
    }
    Ok(())
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
    if !RuntimeLiveStoreIdentity::canonical().is_exact_match(
        &config.provider_bind_address,
        &config.endpoint,
        &config.namespace,
    ) {
        return Err(MaterializeError::Contract(
            "generation.json target is not the canonical runtime-live Store identity".to_owned(),
        ));
    }
    Ok(config)
}

fn validate_materializer_selection(
    input: &CanarySourceBundleMaterializeInput,
    selection: &ProfileSelectionResolution,
) -> Result<(), MaterializeError> {
    let profile = input.profile_selection.profile;
    selection
        .roots
        .validate(profile)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    selection
        .roots
        .validate_source_bundle_root(input.profile_selection.source_root.as_str())
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    validate_absolute(&input.output_bundle, "output_bundle")?;
    validate_absolute(&input.store_path, "store_path")?;
    validate_absolute(Path::new(input.staging_root.as_str()), "staging_root")?;
    selection
        .roots
        .admits_write_target(input.output_bundle.to_string_lossy().as_ref())
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    selection
        .roots
        .admits_write_target(input.store_path.to_string_lossy().as_ref())
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    selection
        .roots
        .admits_write_target(input.staging_root.as_str())
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let governance_roots = &selection.governance.roots;
    if selection.governance.profile != profile
        || governance_roots.immutable_binaries != selection.roots.immutable_binaries
        || governance_roots.durable_data != selection.roots.durable_data
        || governance_roots.user_config != selection.roots.user_config
        || governance_roots.user_cache != selection.roots.user_cache
        || selection.roots.runtime_state_roots.profile_anchor_root
            != input.profile_selection.profile_anchor_root
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(input.staging_root.as_str()),
            Path::new(input.profile_selection.staging_root.as_str()),
        )
        || (input.profile_selection.profile == InstallationProfile::PortableDev
            && input.profile_selection.generation.as_deref() != Some(input.generation.as_str()))
        || !eliot_platform_windows::windows_paths_equal(
            &input.output_bundle,
            Path::new(input.profile_selection.source_root.as_str()),
        )
    {
        return Err(MaterializeError::Invalid(
            "resolved profile binding, generation, or publication path differs from the materializer selection"
                .to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct PhaseAPeerIdentity {
    sid: String,
    session_id: u32,
}

impl PhaseAPeerIdentity {
    fn derive(
        input: &CanarySourceBundleMaterializeInput,
        selection: &ProfileSelectionResolution,
        selected_profile_anchor: &SelectedProfileAnchor<'_>,
    ) -> Result<Self, MaterializeError> {
        if input.profile_selection.profile != selection.governance.profile {
            return Err(MaterializeError::Invalid(
                "profile selection differs from the resolved profile".to_owned(),
            ));
        }

        match selection.governance.profile {
            InstallationProfile::SystemService => Ok(Self {
                sid: LOCAL_SERVICE_SID.to_owned(),
                session_id: 0,
            }),
            InstallationProfile::UserMode | InstallationProfile::PortableDev => {
                selected_profile_anchor.revalidate()?;
                let expected = eliot_platform_windows::current_process_named_pipe_expectation()
                    .map_err(|error| MaterializeError::Platform(error.to_string()))?;

                match selection.governance.profile {
                    InstallationProfile::UserMode => {
                        let local_app_data =
                            eliot_platform_windows::current_user_local_app_data_root()
                                .map_err(|error| MaterializeError::Platform(error.to_string()))?;
                        if !eliot_platform_windows::windows_paths_equal(
                            &local_app_data,
                            Path::new(input.profile_selection.anchors.local_app_data.as_str()),
                        ) {
                            return Err(MaterializeError::Invalid(
                                "selected LocalAppData differs from the OS current-user anchor"
                                    .to_owned(),
                            ));
                        }
                        let profile_anchor =
                            Path::new(input.profile_selection.profile_anchor_root.as_str());
                        if !eliot_platform_windows::windows_paths_equal(
                            &local_app_data,
                            profile_anchor,
                        ) || !eliot_platform_windows::windows_paths_equal(
                            &local_app_data,
                            &selected_profile_anchor.canonical_path,
                        ) {
                            return Err(MaterializeError::Invalid(
                                "UserMode profile anchor differs from OS current-user LocalAppData"
                                    .to_owned(),
                            ));
                        }
                    }
                    InstallationProfile::PortableDev => {
                        let repository_root = input
                            .profile_selection
                            .anchors
                            .repository_root
                            .as_ref()
                            .ok_or_else(|| {
                                MaterializeError::Invalid(
                                    "PortableDev profile requires a selected repository root"
                                        .to_owned(),
                                )
                            })?;
                        let selected_root = Path::new(repository_root.as_str());
                        if !eliot_platform_windows::windows_paths_equal(
                            selected_root,
                            Path::new(input.profile_selection.profile_anchor_root.as_str()),
                        ) || !eliot_platform_windows::windows_paths_equal(
                            selected_root,
                            &selected_profile_anchor.canonical_path,
                        ) {
                            return Err(MaterializeError::Invalid(
                                "PortableDev repository root differs from the retained profile anchor"
                                    .to_owned(),
                            ));
                        }
                    }
                    InstallationProfile::SystemService => unreachable!(),
                }

                selected_profile_anchor.revalidate()?;

                Ok(Self {
                    sid: expected.expected_sid().to_owned(),
                    session_id: expected.expected_session_id(),
                })
            }
        }
    }
}

fn governor_bytes(
    generation: &PlatformHandle,
    installation_epoch: &InstallationEpoch,
    kernel_sha256: &str,
    kernel_principal: &str,
) -> Result<Vec<u8>, MaterializeError> {
    let generation_number = ResourceGeneration::new(1)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let authority_epoch = materializer_genesis_epoch()?;
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
            principal: kernel_principal.to_owned(),
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

fn protected_snapshot_digest_from_governor_bytes(
    bytes: &[u8],
) -> Result<PlatformHandle, MaterializeError> {
    let config: GovernorLaunchConfig = serde_json::from_slice(bytes).map_err(|error| {
        MaterializeError::Contract(format!("parse protected snapshot identity: {error}"))
    })?;
    config.validate().map_err(|error| {
        MaterializeError::Contract(format!("validate protected snapshot identity: {error}"))
    })?;
    PlatformHandle::new(config.protected_snapshot_digest).map_err(|error| {
        MaterializeError::Contract(format!("protected snapshot identity: {error}"))
    })
}

fn bridge_source_plan(
    input: &CanarySourceBundleMaterializeInput,
    kernel_artifact_sha256: &str,
    protected_snapshot_digest: &str,
) -> Result<Option<Box<AgentBridgeSourceMaterializationPlan>>, MaterializeError> {
    match (
        input.agent_bridge_exe.as_ref(),
        input.agent_bridge_account.as_deref(),
    ) {
        (None, None) => Ok(None),
        (Some(path), Some(account)) => {
            if path.file_name().and_then(|name| name.to_str()) != Some("eliot-agent-bridge.exe") {
                return Err(MaterializeError::Invalid(
                    "agent_bridge_exe must name eliot-agent-bridge.exe".to_owned(),
                ));
            }
            let path = handle_path(path, "agent_bridge_exe")?;
            let retained = AgentBridgeSourceMaterializationFactory::retain_source(&path)
                .map_err(|error| MaterializeError::Platform(error.to_string()))?;
            let approved_user_sid = resolve_account_sid(account).map_err(|error| {
                MaterializeError::Invalid(format!(
                    "agent_bridge_account could not be resolved to a canonical SID: {error}"
                ))
            })?;
            let plan = agent_bridge_source_plan_from_observed_kernel(
                &retained,
                approved_user_sid,
                kernel_artifact_sha256,
                protected_snapshot_digest,
            )
            .map_err(|error| MaterializeError::Contract(error.to_string()))?;
            Ok(Some(Box::new(plan)))
        }
        _ => Err(MaterializeError::Invalid(
            "agent_bridge_exe and agent_bridge_account must be supplied together".to_owned(),
        )),
    }
}

/// Rebuilds the optional bridge source plan after the durable Phase-A
/// publication readback.  The Kernel artifact digest is taken from that
/// receipt, never from a caller-supplied value.
pub(crate) fn bridge_source_plan_for_receipt(
    input: &CanarySourceBundleMaterializeInput,
    receipt: &CanarySourceBundleReceipt,
) -> Result<Option<Box<AgentBridgeSourceMaterializationPlan>>, InstallationError> {
    let kernel_sha256 = receipt
        .files
        .iter()
        .find(|file| file.relative_path == "eliot-kernel.exe")
        .map(|file| file.sha256.as_str())
        .ok_or_else(|| {
            InstallationError::IncompleteObservation("kernel receipt role missing".to_owned())
        })?;
    let protected_snapshot_digest = sha256_hex(
        format!(
            "governor-protected:{}:{}:{}",
            input.installation_epoch.installation.as_str(),
            input.generation.as_str(),
            kernel_sha256,
        )
        .as_bytes(),
    );
    bridge_source_plan(input, kernel_sha256, &protected_snapshot_digest)
        .map_err(InstallationError::from)
}

#[allow(
    clippy::too_many_lines,
    reason = "the typed bundle seam keeps all launch and evidence bindings auditable"
)]
#[cfg(test)]
fn build_typed_bundle(
    input: &CanarySourceBundleMaterializeInput,
    executables: &[ValidatedExecutable],
) -> Result<TypedBundle, MaterializeError> {
    let selection = GenerationPackagePlanner::resolve_profile_selection(&input.profile_selection)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let (anchor_identity, anchor_handle) = open_no_follow_directory(Path::new(
        input.profile_selection.profile_anchor_root.as_str(),
    ))
    .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    let selected_profile_anchor =
        SelectedProfileAnchor::retain(input, &selection, &anchor_handle, anchor_identity)?;
    build_typed_bundle_with_selection(input, executables, &selection, &selected_profile_anchor)
}

struct GovernedBundlePaths {
    host: PlatformHandle,
    watchdog: PlatformHandle,
    store_bridge: PlatformHandle,
    canonical_store: PlatformHandle,
    eliotd: PlatformHandle,
    doctor: PlatformHandle,
    testd: PlatformHandle,
    native_worker: PlatformHandle,
    wasm_host: PlatformHandle,
    user_broker: PlatformHandle,
    store_config: PlatformHandle,
    governor_config: PlatformHandle,
    eliotd_descriptor: PlatformHandle,
    authority_descriptor: PlatformHandle,
    store_bootstrap: PlatformHandle,
}

impl GovernedBundlePaths {
    fn resolve(selection: &ProfileSelectionResolution) -> Result<Self, MaterializeError> {
        let immutable_generation_root = Path::new(&selection.roots.immutable_binaries);
        let role_path = |role: &str| {
            handle_path(
                &immutable_generation_root.join(role),
                "profile-governed immutable destination",
            )
        };
        let host = role_path("eliot-host.exe")?;
        let watchdog = role_path("eliot-watchdog.exe")?;
        let store_bridge = role_path("eliot-store-surreal.exe")?;
        let canonical_store = role_path("surreal.exe")?;
        let eliotd = role_path("eliotd.exe")?;
        let doctor = role_path("eliot-doctor.exe")?;
        let testd = role_path("eliot-testd.exe")?;
        let native_worker = role_path("eliot-native-worker.exe")?;
        let wasm_host = role_path("eliot-wasm-host.exe")?;
        let user_broker = role_path("eliot-user-broker.exe")?;
        let store_config = role_path("generation.json")?;
        let governor_config = role_path("eliotd-governor.json")?;
        let eliotd_descriptor = role_path("eliotd.json")?;
        let authority_descriptor = role_path("authority.json")?;
        let store_bootstrap = role_path("store-bootstrap.json")?;
        Ok(Self {
            host,
            watchdog,
            store_bridge,
            canonical_store,
            eliotd,
            doctor,
            testd,
            native_worker,
            wasm_host,
            user_broker,
            store_config,
            governor_config,
            eliotd_descriptor,
            authority_descriptor,
            store_bootstrap,
        })
    }
}

struct BundleExecutables<'a> {
    kernel: &'a ValidatedExecutable,
    host: &'a ValidatedExecutable,
    watchdog: &'a ValidatedExecutable,
    store_bridge: &'a ValidatedExecutable,
    canonical_store: &'a ValidatedExecutable,
    eliotd: &'a ValidatedExecutable,
    doctor: &'a ValidatedExecutable,
    testd: &'a ValidatedExecutable,
    native_worker: &'a ValidatedExecutable,
    wasm_host: &'a ValidatedExecutable,
    user_broker: &'a ValidatedExecutable,
}

impl<'a> BundleExecutables<'a> {
    fn resolve(executables: &'a [ValidatedExecutable]) -> Result<Self, MaterializeError> {
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
        let doctor = by_name("eliot-doctor.exe")?;
        let testd = by_name("eliot-testd.exe")?;
        let native_worker = by_name("eliot-native-worker.exe")?;
        let wasm_host = by_name("eliot-wasm-host.exe")?;
        let user_broker = by_name("eliot-user-broker.exe")?;
        Ok(Self {
            kernel,
            host,
            watchdog,
            store_bridge,
            canonical_store,
            eliotd,
            doctor,
            testd,
            native_worker,
            wasm_host,
            user_broker,
        })
    }
}

fn executable_by_name<'a>(
    executables: &'a [ValidatedExecutable],
    name: &str,
) -> Result<&'a ValidatedExecutable, MaterializeError> {
    executables
        .iter()
        .find(|item| item.name == name)
        .ok_or_else(|| MaterializeError::Invalid(format!("missing executable {name}")))
}

struct BundleTemplateIdentity {
    governor_bytes: Vec<u8>,
    protected_snapshot_digest: PlatformHandle,
    governor_sha256: String,
    launch_nonce: PlatformHandle,
    credential_token: String,
    store_credential_target: PlatformHandle,
    authority_generation: ResourceGeneration,
    authority_epoch: EpochId,
    authority_state_fence: StateFence,
}

impl BundleTemplateIdentity {
    fn derive(
        input: &CanarySourceBundleMaterializeInput,
        executables: &BundleExecutables<'_>,
        peer_identity: &PhaseAPeerIdentity,
    ) -> Result<Self, MaterializeError> {
        let governor_bytes = governor_bytes(
            &input.generation,
            &input.installation_epoch,
            &executables.kernel.sha256,
            &peer_identity.sid,
        )?;
        let protected_snapshot_digest =
            protected_snapshot_digest_from_governor_bytes(&governor_bytes)?;
        bridge_source_plan(
            input,
            &executables.kernel.sha256,
            protected_snapshot_digest.as_str(),
        )?;
        let governor_sha256 = sha256_hex(&governor_bytes);
        let template_facts =
            phase_a_template_facts(executables, governor_bytes.len(), &governor_sha256)?;
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
        let launch_nonce = make_digest(
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
        let authority_epoch = materializer_genesis_epoch()?;
        let authority_state_fence = StateFence::new(authority_epoch.clone(), authority_generation);
        Ok(Self {
            governor_bytes,
            protected_snapshot_digest,
            governor_sha256,
            launch_nonce,
            credential_token,
            store_credential_target,
            authority_generation,
            authority_epoch,
            authority_state_fence,
        })
    }
}

fn phase_a_template_facts(
    executables: &BundleExecutables<'_>,
    governor_size: usize,
    governor_sha256: &str,
) -> Result<Vec<PackageArtifactDigest>, MaterializeError> {
    Ok(vec![
        package_digest(
            "eliot-host.exe",
            executables.host.size,
            &executables.host.sha256,
        )?,
        package_digest(
            "eliot-watchdog.exe",
            executables.watchdog.size,
            &executables.watchdog.sha256,
        )?,
        package_digest(
            "eliot-kernel.exe",
            executables.kernel.size,
            &executables.kernel.sha256,
        )?,
        package_digest(
            "eliot-store-surreal.exe",
            executables.store_bridge.size,
            &executables.store_bridge.sha256,
        )?,
        package_digest(
            "surreal.exe",
            executables.canonical_store.size,
            &executables.canonical_store.sha256,
        )?,
        package_digest(
            "eliotd.exe",
            executables.eliotd.size,
            &executables.eliotd.sha256,
        )?,
        package_digest(
            "eliot-doctor.exe",
            executables.doctor.size,
            &executables.doctor.sha256,
        )?,
        package_digest(
            "eliot-testd.exe",
            executables.testd.size,
            &executables.testd.sha256,
        )?,
        package_digest(
            "eliot-native-worker.exe",
            executables.native_worker.size,
            &executables.native_worker.sha256,
        )?,
        package_digest(
            "eliot-wasm-host.exe",
            executables.wasm_host.size,
            &executables.wasm_host.sha256,
        )?,
        package_digest(
            "eliot-user-broker.exe",
            executables.user_broker.size,
            &executables.user_broker.sha256,
        )?,
        package_digest(
            "eliotd-governor.json",
            governor_size as u64,
            governor_sha256,
        )?,
    ])
}

struct TypedBundleBuildContext<'a> {
    input: &'a CanarySourceBundleMaterializeInput,
    executables: &'a [ValidatedExecutable],
    selection: &'a ProfileSelectionResolution,
    paths: GovernedBundlePaths,
    named_executables: BundleExecutables<'a>,
    peer_identity: PhaseAPeerIdentity,
    template: BundleTemplateIdentity,
}

impl<'a> TypedBundleBuildContext<'a> {
    fn new(
        input: &'a CanarySourceBundleMaterializeInput,
        executables: &'a [ValidatedExecutable],
        selection: &'a ProfileSelectionResolution,
        selected_profile_anchor: &SelectedProfileAnchor<'_>,
    ) -> Result<Self, MaterializeError> {
        let paths = GovernedBundlePaths::resolve(selection)?;
        let named_executables = BundleExecutables::resolve(executables)?;
        let peer_identity = PhaseAPeerIdentity::derive(input, selection, selected_profile_anchor)?;
        let template = BundleTemplateIdentity::derive(input, &named_executables, &peer_identity)?;
        Ok(Self {
            input,
            executables,
            selection,
            paths,
            named_executables,
            peer_identity,
            template,
        })
    }
}

struct RuntimeLaunchArguments {
    kernel: Vec<PlatformHandle>,
    store_bridge: Vec<PlatformHandle>,
    canonical_store: Vec<PlatformHandle>,
}

impl RuntimeLaunchArguments {
    fn build(context: &TypedBundleBuildContext<'_>) -> Result<Self, MaterializeError> {
        let roots = &context.selection.roots.runtime_state_roots;
        let profile = context.selection.governance.profile;
        let kernel = &context.named_executables.kernel;
        let doctor = &context.named_executables.doctor;
        let testd = &context.named_executables.testd;
        let native_worker = &context.named_executables.native_worker;
        let kernel_arguments = make_args([
            "--work-root".to_owned(),
            roots.kernel_work_root.as_str().to_owned(),
            "--store-bootstrap".to_owned(),
            context.paths.store_bootstrap.as_str().to_owned(),
            "--store-bootstrap-sha256".to_owned(),
            PHASE_B_PENDING_MARKER.to_owned(),
            "--authority-descriptor".to_owned(),
            context.paths.authority_descriptor.as_str().to_owned(),
            "--authority-descriptor-sha256".to_owned(),
            PHASE_B_PENDING_MARKER.to_owned(),
            "--kernel-artifact-sha256".to_owned(),
            kernel.sha256.clone(),
            "--doctor-artifact-sha256".to_owned(),
            doctor.sha256.clone(),
            "--testd-artifact-sha256".to_owned(),
            testd.sha256.clone(),
            "--native-worker-artifact-sha256".to_owned(),
            native_worker.sha256.clone(),
            "--user-broker-executable".to_owned(),
            context.paths.user_broker.as_str().to_owned(),
            "--user-broker-artifact-sha256".to_owned(),
            context.named_executables.user_broker.sha256.clone(),
            "--eliotd-descriptor".to_owned(),
            context.paths.eliotd_descriptor.as_str().to_owned(),
            "--eliotd-descriptor-sha256".to_owned(),
            "0".repeat(64),
        ])?;
        let store_bridge_arguments = match profile {
            InstallationProfile::PortableDev => make_args([
                "--portable-dev-root".to_owned(),
                context
                    .input
                    .profile_selection
                    .profile_anchor_root
                    .as_str()
                    .to_owned(),
                "--config".to_owned(),
                context.paths.store_config.as_str().to_owned(),
            ])?,
            InstallationProfile::SystemService | InstallationProfile::UserMode => make_args([
                "--config".to_owned(),
                context.paths.store_config.as_str().to_owned(),
            ])?,
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
        Ok(Self {
            kernel: kernel_arguments,
            store_bridge: store_bridge_arguments,
            canonical_store: canonical_store_arguments,
        })
    }

    fn bind_descriptor_digest(mut self, descriptor_sha256: &str) -> Result<Self, MaterializeError> {
        self.kernel = self
            .kernel
            .into_iter()
            .map(|argument| {
                if argument.as_str() == "0".repeat(64) {
                    PlatformHandle::new(descriptor_sha256.to_owned()).map_err(|error| {
                        MaterializeError::Contract(format!("kernel descriptor digest: {error}"))
                    })
                } else {
                    Ok(argument)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self)
    }
}

fn eliotd_descriptor_binding(
    context: &TypedBundleBuildContext<'_>,
) -> Result<(Vec<u8>, String), MaterializeError> {
    let roots = &context.selection.roots.runtime_state_roots;
    let descriptor = EliotdLaunchDescriptor {
        wire_id: ELIOTD_LAUNCH_DESCRIPTOR_WIRE_ID.to_owned(),
        wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
        executable: context.paths.eliotd.clone(),
        executable_sha256: context.named_executables.eliotd.sha256.clone(),
        arguments: make_args([
            "--config-descriptor".to_owned(),
            context.paths.governor_config.as_str().to_owned(),
            "--config-descriptor-sha256".to_owned(),
            context.template.governor_sha256.clone(),
            "--launch-nonce".to_owned(),
            context.template.launch_nonce.as_str().to_owned(),
            "--executable-sha256".to_owned(),
            context.named_executables.eliotd.sha256.clone(),
        ])?,
        working_directory: roots.kernel_work_root.clone(),
        config_descriptor: context.paths.governor_config.clone(),
        config_descriptor_sha256: context.template.governor_sha256.clone(),
        protected_snapshot_digest: context
            .template
            .protected_snapshot_digest
            .as_str()
            .to_owned(),
        launch_nonce: context.template.launch_nonce.clone(),
        authority_epoch: context.template.authority_epoch.clone(),
        generation: context.template.authority_generation,
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
    Ok((descriptor_bytes, descriptor_sha256))
}

fn runtime_launch_descriptor(
    context: &TypedBundleBuildContext<'_>,
    arguments: RuntimeLaunchArguments,
    descriptor_sha256: &str,
) -> Result<RuntimeLaunchDescriptor, MaterializeError> {
    let input = context.input;
    let paths = &context.paths;
    let executables = &context.named_executables;
    let template = &context.template;
    let roots = context.selection.roots.runtime_state_roots.clone();
    let profile = context.selection.governance.profile;
    let supervision_lease_scope_id = PlatformHandle::new(format!(
        "eliot-supervision-scope:v1:{}:{}",
        input.installation_epoch.installation, input.generation
    ))
    .map_err(|error| MaterializeError::Contract(format!("supervision scope id: {error}")))?;
    RuntimeLaunchDescriptor {
        profile,
        profile_component: PlatformHandle::new(input.profile_selection.component.clone())
            .map_err(|error| MaterializeError::Contract(error.to_string()))?,
        profile_version: PlatformHandle::new(input.profile_selection.version.clone())
            .map_err(|error| MaterializeError::Contract(error.to_string()))?,
        profile_installation_key: input.profile_selection.installation_key.clone(),
        profile_governed_roots: context.selection.roots.clone(),
        portable_root: (profile == InstallationProfile::PortableDev)
            .then(|| input.profile_selection.profile_anchor_root.clone()),
        installation_epoch: input.installation_epoch.clone(),
        generation: input.generation.clone(),
        authority_generation: template.authority_generation,
        authority_state_fence: template.authority_state_fence.clone(),
        supervision_authority: SupervisionAuthorityBinding::Pending {
            supervision_lease_scope_id,
        },
        authority_descriptor_path: paths.authority_descriptor.clone(),
        authority_descriptor_digest: PlatformHandle::new(PHASE_B_PENDING_MARKER)
            .map_err(|error| MaterializeError::Contract(error.to_string()))?,
        runtime_state_roots: roots.clone(),
        kernel_work_root: roots.kernel_work_root.clone(),
        kernel_artifact_digest: make_digest(executables.kernel.sha256.clone(), "kernel digest")?,
        eliotd_executable_path: paths.eliotd.clone(),
        eliotd_artifact_digest: make_digest(executables.eliotd.sha256.clone(), "eliotd digest")?,
        eliotd_config_path: paths.governor_config.clone(),
        eliotd_config_digest: make_digest(template.governor_sha256.clone(), "governor digest")?,
        protected_snapshot_digest: template.protected_snapshot_digest.clone(),
        eliotd_descriptor_path: paths.eliotd_descriptor.clone(),
        eliotd_descriptor_digest: make_digest(descriptor_sha256.to_owned(), "descriptor digest")?,
        eliotd_launch_nonce: template.launch_nonce.clone(),
        store_config_path: paths.store_config.clone(),
        store_credential_target: template.store_credential_target.clone(),
        store_bridge_executable_path: paths.store_bridge.clone(),
        store_bridge_artifact_digest: make_digest(
            executables.store_bridge.sha256.clone(),
            "Store bridge digest",
        )?,
        store_bootstrap_descriptor_path: paths.store_bootstrap.clone(),
        store_bootstrap_descriptor_digest: PlatformHandle::new(PHASE_B_PENDING_MARKER)
            .map_err(|error| MaterializeError::Contract(error.to_string()))?,
        canonical_store_executable_path: paths.canonical_store.clone(),
        canonical_store_artifact_digest: make_digest(
            executables.canonical_store.sha256.clone(),
            "Surreal digest",
        )?,
        kernel_arguments: arguments.kernel,
        store_bridge_arguments: arguments.store_bridge,
        canonical_store_arguments: arguments.canonical_store,
        host_executable_path: paths.host.clone(),
        host_artifact_digest: make_digest(executables.host.sha256.clone(), "Host digest")?,
        watchdog_executable_path: paths.watchdog.clone(),
        watchdog_artifact_digest: make_digest(
            executables.watchdog.sha256.clone(),
            "Watchdog digest",
        )?,
        doctor_artifact_digest: make_digest(executables.doctor.sha256.clone(), "Doctor digest")?,
        testd_artifact_digest: make_digest(executables.testd.sha256.clone(), "Testd digest")?,
        native_worker_artifact_digest: make_digest(
            executables.native_worker.sha256.clone(),
            "Native worker digest",
        )?,
        wasm_host_artifact_digest: make_digest(
            executables.wasm_host.sha256.clone(),
            "WASM host digest",
        )?,
        user_broker_artifact_digest: make_digest(
            executables.user_broker.sha256.clone(),
            "User Broker digest",
        )?,
        doctor_executable_path: paths.doctor.clone(),
        testd_executable_path: paths.testd.clone(),
        native_worker_executable_path: paths.native_worker.clone(),
        wasm_host_executable_path: paths.wasm_host.clone(),
        user_broker_executable_path: paths.user_broker.clone(),
        descriptor_digest: PlatformHandle::new("0".repeat(64))
            .map_err(|error| MaterializeError::Contract(error.to_string()))?,
    }
    .with_computed_digest()
    .map_err(|error| MaterializeError::Contract(format!("runtime launch: {error}")))
}

fn store_config_bytes(
    context: &TypedBundleBuildContext<'_>,
    runtime_launch: &RuntimeLaunchDescriptor,
) -> Result<Vec<u8>, MaterializeError> {
    let admitted_store_target = &runtime_launch.store_credential_target;
    let credential_ref = admitted_store_target.as_str().to_owned();
    // I15.4 requires the provider bootstrap/admin credential to be a separate,
    // independently rotatable reference from the ordinary client credential.
    // The installation secret-provisioning owner derives it from the exact
    // Store locator, in its own reserved namespace, so no value and no second
    // derivation rule exists in this composition root.
    let provider_bootstrap_credential_ref =
        provider_bootstrap_credential_target_for_store_target(admitted_store_target)
            .map_err(|error| {
                MaterializeError::Contract(format!("provider bootstrap target: {error}"))
            })?
            .as_str()
            .to_owned();
    let mut store_config = StoreLaunchConfig {
        store_pipe: format!(
            r"\\.\pipe\eliot\store-{}",
            context.template.credential_token
        ),
        launch_nonce: format!("store:{}", context.template.credential_token),
        expected_client_sid: context.peer_identity.sid.clone(),
        expected_client_session_id: context.peer_identity.session_id,
        approved_artifact_hash: context.named_executables.store_bridge.sha256.clone(),
        approved_config_hash: String::new(),
        endpoint: RUNTIME_LIVE_STORE_ENDPOINT.to_owned(),
        provider_bind_address: RUNTIME_LIVE_STORE_BIND.to_owned(),
        namespace: RUNTIME_LIVE_STORE_NAMESPACE.to_owned(),
        database: "eliot".to_owned(),
        username: "store".to_owned(),
        connect_timeout_ms: 10_000,
        query_timeout_ms: 10_000,
        // Cross-scope mechanical line (installer lane file): new optional
        // bridge knob defaults to the I5.7 desktop default; behavior unchanged.
        store_transaction_limit: None,
        schema_generation: "1.0.0".to_owned(),
        blob_root: Path::new(
            context
                .selection
                .roots
                .runtime_state_roots
                .store_data_root
                .as_str(),
        )
        .join("blob")
        .to_string_lossy()
        .into_owned(),
        instance_id: format!("store-{}", context.input.generation.as_str()),
        credential_ref,
        provider_bootstrap_credential_ref,
        provider_bootstrap_username: "provider-bootstrap".to_owned(),
        runtime_launch: runtime_launch.clone(),
    };
    store_config.approved_config_hash = launch_config_digest(&store_config)
        .map_err(|error| MaterializeError::Contract(format!("Store config digest: {error}")))?;
    store_config
        .validate_materialized_at(Path::new(runtime_launch.store_config_path.as_str()))
        .map_err(|error| MaterializeError::Contract(format!("Store config: {error}")))?;
    let generation_bytes = serde_json::to_vec(&store_config)
        .map_err(|error| MaterializeError::Contract(format!("serialize Store config: {error}")))?;
    validate_store_config_bytes(&generation_bytes, runtime_launch)?;
    Ok(generation_bytes)
}

fn package_inventory(
    context: &TypedBundleBuildContext<'_>,
    json_roles: &[JsonRole],
) -> Result<(Vec<PackageArtifactDigest>, PackageManifest, PlatformHandle), MaterializeError> {
    let mut expected = Vec::with_capacity(REQUIRED_ROLES.len());
    for (role, executable) in REQUIRED_ROLES {
        let (size, digest) = if executable {
            let executable = executable_by_name(context.executables, role)?;
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
    let manifest = PackageManifest::new(context.input.generation.as_str(), specs)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let evidence_digest =
        GenerationPackagePlanner::artifact_set_evidence_digest(&manifest, &expected)
            .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    Ok((expected, manifest, evidence_digest))
}

fn build_typed_bundle_with_selection(
    input: &CanarySourceBundleMaterializeInput,
    executables: &[ValidatedExecutable],
    selection: &ProfileSelectionResolution,
    selected_profile_anchor: &SelectedProfileAnchor<'_>,
) -> Result<TypedBundle, MaterializeError> {
    let context =
        TypedBundleBuildContext::new(input, executables, selection, selected_profile_anchor)?;
    let arguments = RuntimeLaunchArguments::build(&context)?;
    let (descriptor_bytes, descriptor_sha256) = eliotd_descriptor_binding(&context)?;
    let arguments = arguments.bind_descriptor_digest(&descriptor_sha256)?;
    let runtime_launch = runtime_launch_descriptor(&context, arguments, &descriptor_sha256)?;
    let generation_bytes = store_config_bytes(&context, &runtime_launch)?;
    let json_roles = vec![
        JsonRole {
            name: "generation.json",
            bytes: generation_bytes,
        },
        JsonRole {
            name: "eliotd-governor.json",
            bytes: context.template.governor_bytes.clone(),
        },
        JsonRole {
            name: "eliotd.json",
            bytes: descriptor_bytes,
        },
    ];
    let (expected, manifest, evidence_digest) = package_inventory(&context, &json_roles)?;
    Ok(TypedBundle {
        json_roles,
        expected,
        manifest,
        evidence_digest,
        profile_governed_roots: selection.roots.clone(),
    })
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), MaterializeError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        // The retained native publication root blocks rename/delete of the
        // directory.  These child opens add the matching no-follow and
        // no-delete-sharing fence for every role file.
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH);
    }
    let mut file = options.open(path).map_err(|error| {
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
    eliot_platform_windows::sync_directory_for_publication(path)
        .map_err(|error| MaterializeError::Platform(format!("sync temporary bundle: {error}")))
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

fn journal_roles_from_precommit(
    files: &[MaterializedRolePrecommitReceipt],
) -> Result<Vec<SourceBundlePublicationRole>, MaterializeError> {
    files
        .iter()
        .map(|file| {
            Ok(SourceBundlePublicationRole {
                relative_path: file.relative_path.clone(),
                executable: file.executable,
                size: file.size,
                sha256: PlatformHandle::new(file.sha256.clone()).map_err(|error| {
                    MaterializeError::Contract(format!(
                        "publication role digest {}: {error}",
                        file.relative_path
                    ))
                })?,
                source_identity: file.source_identity,
                temporary_identity: file.temporary_identity,
                pe: file.pe.clone(),
                authenticode: file.authenticode.clone(),
            })
        })
        .collect()
}

fn precommit_from_journal(
    files: &[SourceBundlePublicationRole],
) -> Vec<MaterializedRolePrecommitReceipt> {
    files
        .iter()
        .map(|file| MaterializedRolePrecommitReceipt {
            relative_path: file.relative_path.clone(),
            executable: file.executable,
            size: file.size,
            sha256: file.sha256.as_str().to_owned(),
            source_identity: file.source_identity,
            temporary_identity: file.temporary_identity,
            pe: file.pe.clone(),
            authenticode: file.authenticode.clone(),
        })
        .collect()
}

fn typed_bundle_from_journal(
    journal: &SourceBundlePublicationJournal,
) -> Result<
    (
        PackageManifest,
        Vec<PackageArtifactDigest>,
        Vec<MaterializedRolePrecommitReceipt>,
    ),
    MaterializeError,
> {
    if journal.precommit_files.len() != REQUIRED_ROLES.len() {
        return Err(MaterializeError::Invalid(
            "publication journal does not retain the complete fifteen-role inventory".to_owned(),
        ));
    }
    let mut manifest_files = Vec::with_capacity(REQUIRED_ROLES.len());
    let mut expected = Vec::with_capacity(REQUIRED_ROLES.len());
    for (role, executable) in REQUIRED_ROLES {
        let fact = journal
            .precommit_files
            .iter()
            .find(|fact| fact.relative_path == role)
            .ok_or_else(|| MaterializeError::Invalid(format!("journal role missing: {role}")))?;
        if fact.executable != executable {
            return Err(MaterializeError::Invalid(format!(
                "journal executable binding differs for {role}"
            )));
        }
        manifest_files.push(
            PackageFileSpec::new(role, executable, fact.size)
                .map_err(|error| MaterializeError::Contract(error.to_string()))?,
        );
        expected.push(PackageArtifactDigest {
            relative_path: role.to_owned(),
            expected_size: fact.size,
            sha256: PlatformHandle::new(fact.sha256.as_str().to_owned())
                .map_err(|error| MaterializeError::Contract(error.to_string()))?,
        });
    }
    let manifest = PackageManifest::new(Path::new(journal.generation.as_str()), manifest_files)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    if manifest.canonical_digest() != journal.manifest_digest.as_str() {
        return Err(MaterializeError::Invalid(
            "publication journal manifest digest does not match its role inventory".to_owned(),
        ));
    }
    let evidence = GenerationPackagePlanner::artifact_set_evidence_digest(&manifest, &expected)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    if evidence != journal.evidence_digest {
        return Err(MaterializeError::Invalid(
            "publication journal evidence digest does not match its role inventory".to_owned(),
        ));
    }
    Ok((
        manifest,
        expected,
        precommit_from_journal(&journal.precommit_files),
    ))
}

fn reconcile_journal_destination(
    journal: &SourceBundlePublicationJournal,
    selected_profile_anchor: &SelectedProfileAnchor<'_>,
) -> Result<Option<CanarySourceBundleReceipt>, MaterializeError> {
    let (manifest, expected, precommit_files) = typed_bundle_from_journal(journal)?;
    let destination = &journal.output_bundle;
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(MaterializeError::Invalid(
                "published bundle path is not a directory".to_owned(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(MaterializeError::Platform(error.to_string())),
    }
    let (destination_identity, _destination_handle) = open_no_follow_directory(destination)
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    if destination_identity != journal.source_identity {
        return Err(MaterializeError::Invalid(
            "published bundle directory identity differs from the durable journal".to_owned(),
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        MaterializeError::Invalid("published bundle has no destination parent".to_owned())
    })?;
    let canonical_parent = canonical_windows_path(parent)
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    let (parent_identity, _parent_handle) = open_no_follow_directory(&canonical_parent)
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    let bundle = TrustedSourceBundle::open(destination)
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    if bundle.identity() != destination_identity {
        return Err(MaterializeError::Invalid(
            "published bundle retained identity differs from readback".to_owned(),
        ));
    }
    let observed = validate_published_observation(&bundle, &manifest, &expected)?;
    let mut files = Vec::with_capacity(REQUIRED_ROLES.len());
    for prepared in &precommit_files {
        let actual = observed.get(&prepared.relative_path).ok_or_else(|| {
            MaterializeError::Invalid(format!(
                "published role missing during journal reconciliation: {}",
                prepared.relative_path
            ))
        })?;
        if actual.identity != prepared.temporary_identity {
            return Err(MaterializeError::Invalid(format!(
                "published role identity differs during journal reconciliation: {}",
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
    let directory_publication = DirectoryPublicationReceipt {
        destination_path: destination.to_string_lossy().into_owned(),
        canonical_parent_path: canonical_parent.to_string_lossy().into_owned(),
        parent_identity,
        source_identity: journal.source_identity,
        destination_identity,
    };
    if journal
        .directory_receipt
        .as_ref()
        .is_some_and(|receipt| receipt != &directory_publication)
    {
        return Err(MaterializeError::Invalid(
            "published bundle directory receipt differs from the durable journal".to_owned(),
        ));
    }
    selected_profile_anchor.revalidate()?;
    Ok(Some(CanarySourceBundleReceipt {
        bundle_path: destination.to_string_lossy().into_owned(),
        generation: journal.generation.as_str().to_owned(),
        profile_governed_roots: journal.profile_governed_roots.clone(),
        evidence_digest: journal.evidence_digest.as_str().to_owned(),
        files,
        source_identity: journal.source_identity,
        directory_publication,
        selected_profile_anchor_path: selected_profile_anchor.path_string(),
        selected_profile_anchor_identity: selected_profile_anchor.identity,
    }))
}

fn journal_unknown_outcome(
    journal: &SourceBundlePublicationJournal,
    precommit_files: Vec<MaterializedRolePrecommitReceipt>,
    diagnostic: String,
    selected_profile_anchor: &SelectedProfileAnchor<'_>,
) -> CanarySourceBundleMaterializeOutcome {
    CanarySourceBundleMaterializeOutcome::CommittedUnknown(CanarySourceBundleReconciliation {
        bundle_path: journal.output_bundle.to_string_lossy().into_owned(),
        generation: journal.generation.as_str().to_owned(),
        profile_governed_roots: journal.profile_governed_roots.clone(),
        evidence_digest: journal.evidence_digest.as_str().to_owned(),
        precommit_files,
        directory_publication: DirectoryPublicationOutcome::CommittedUnknown(
            eliot_platform_windows::DirectoryPublicationUnknownReceipt {
                reason: eliot_platform_windows::DirectoryPublicationUnknown::PostCommitReadbackUnavailable,
                destination_path: journal.output_bundle.to_string_lossy().into_owned(),
                canonical_parent_path: journal
                    .output_bundle
                    .parent()
                    .map_or_else(String::new, |path| path.to_string_lossy().into_owned()),
                parent_identity: journal.parent_identity,
                source_identity: journal.source_identity,
            },
        ),
        reason: CanarySourceBundleReconciliationReason::DirectoryPublicationUnknown,
        diagnostic,
        selected_profile_anchor_path: selected_profile_anchor.path_string(),
        selected_profile_anchor_identity: selected_profile_anchor.identity,
    })
}

fn persist_unknown_publication(
    store: &RedbInstallationTransactionStore,
    journal: &SourceBundlePublicationJournal,
    precommit_files: Vec<MaterializedRolePrecommitReceipt>,
    diagnostic: impl AsRef<str>,
    selected_profile_anchor: &SelectedProfileAnchor<'_>,
) -> Result<CanarySourceBundleMaterializeOutcome, MaterializeError> {
    selected_profile_anchor.revalidate()?;
    let diagnostic = diagnostic.as_ref().chars().take(1024).collect::<String>();
    let unknown = SourceBundlePublicationJournal {
        state: SourceBundlePublicationJournalState::CommittedUnknown,
        destination_identity: None,
        directory_receipt: None,
        diagnostic: Some(diagnostic.clone()),
        ..journal.clone()
    };
    let recorded = store
        .record_source_bundle_publication(&unknown)
        .map_err(|error| MaterializeError::RecoveryRequired {
            operation: journal.operation_id.as_str().to_owned(),
            stage: InstallationRecoveryStage::Recovery,
            source_context: diagnostic.clone(),
            cleanup: Some(format!(
                "durable unknown-publication record failed: {error}"
            )),
        })?;
    Ok(journal_unknown_outcome(
        &recorded,
        precommit_files,
        diagnostic,
        selected_profile_anchor,
    ))
}

fn load_verified_published_receipt(
    store: &RedbInstallationTransactionStore,
    operation_id: &PlatformHandle,
    selected_profile_anchor: &SelectedProfileAnchor<'_>,
) -> Result<CanarySourceBundleReceipt, MaterializeError> {
    let journal = store
        .load_verified_published_source_bundle_publication(operation_id)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    reconcile_journal_destination(&journal, selected_profile_anchor)?.ok_or_else(|| {
        MaterializeError::Invalid(
            "durable Published journal has no exact verified destination".to_owned(),
        )
    })
}

fn verify_resumed_bundle(
    publication: &OwnedDirectoryPublication,
    journal: &SourceBundlePublicationJournal,
    precommit_files: &[MaterializedRolePrecommitReceipt],
    manifest: &PackageManifest,
    expected: &[PackageArtifactDigest],
) -> Result<(), MaterializeError> {
    let bundle = publication.trusted_source_bundle().map_err(|error| {
        MaterializeError::Platform(format!("open resumed source bundle: {error}"))
    })?;
    if bundle.identity() != journal.source_identity {
        return Err(MaterializeError::Invalid(
            "resumed temporary directory identity differs from the durable journal".to_owned(),
        ));
    }
    let observed = validate_published_observation(&bundle, manifest, expected)?;
    for prepared in precommit_files {
        let actual = observed.get(&prepared.relative_path).ok_or_else(|| {
            MaterializeError::Invalid(format!("resumed role missing: {}", prepared.relative_path))
        })?;
        if actual.identity != prepared.temporary_identity
            || actual.size != prepared.size
            || actual.sha256 != prepared.sha256
            || actual.pe != prepared.pe
        {
            return Err(MaterializeError::Invalid(format!(
                "resumed role differs from the durable journal: {}",
                prepared.relative_path
            )));
        }
    }
    Ok(())
}

fn resume_intent_publication(
    store: &RedbInstallationTransactionStore,
    journal: &SourceBundlePublicationJournal,
    precommit_files: Vec<MaterializedRolePrecommitReceipt>,
    selected_profile_anchor: &SelectedProfileAnchor<'_>,
) -> Result<CanarySourceBundleMaterializeOutcome, MaterializeError> {
    selected_profile_anchor.revalidate()?;
    let publication = match OwnedDirectoryPublication::resume(
        &journal.output_bundle,
        &journal.temporary_path,
        &journal.temporary_name,
        journal.parent_identity,
        journal.source_identity,
    ) {
        Ok(publication) => publication,
        Err(error) => {
            return persist_unknown_publication(
                store,
                journal,
                precommit_files,
                format!("recorded temporary publication cannot be resumed: {error}"),
                selected_profile_anchor,
            );
        }
    };
    let (manifest, expected, _) = typed_bundle_from_journal(journal)?;
    if let Err(error) = verify_resumed_bundle(
        &publication,
        journal,
        &precommit_files,
        &manifest,
        &expected,
    ) {
        return persist_unknown_publication(
            store,
            journal,
            precommit_files,
            format!("recorded temporary publication readback rejected: {error}"),
            selected_profile_anchor,
        );
    }
    selected_profile_anchor.revalidate()?;
    let directory_publication = match publication.publish(journal.source_identity) {
        Ok(outcome) => outcome,
        Err(error) => {
            return persist_unknown_publication(
                store,
                journal,
                precommit_files,
                format!("recorded temporary publication move was not authorized: {error}"),
                selected_profile_anchor,
            );
        }
    };
    match directory_publication {
        DirectoryPublicationOutcome::Published(receipt) => {
            selected_profile_anchor.revalidate()?;
            let published = SourceBundlePublicationJournal {
                state: SourceBundlePublicationJournalState::Published,
                destination_identity: Some(receipt.destination_identity),
                directory_receipt: Some(receipt),
                diagnostic: None,
                ..journal.clone()
            };
            let recorded = match store.record_source_bundle_publication(&published) {
                Ok(recorded) => recorded,
                Err(error) => {
                    return persist_unknown_publication(
                        store,
                        journal,
                        precommit_files,
                        format!(
                            "published destination failed durable authority verification: {error}"
                        ),
                        selected_profile_anchor,
                    );
                }
            };
            let receipt = load_verified_published_receipt(
                store,
                &recorded.operation_id,
                selected_profile_anchor,
            )?;
            Ok(CanarySourceBundleMaterializeOutcome::Published(receipt))
        }
        DirectoryPublicationOutcome::CommittedUnknown(receipt) => persist_unknown_publication(
            store,
            journal,
            precommit_files,
            format!(
                "recorded temporary publication committed with unknown outcome: {:?}",
                receipt.reason
            ),
            selected_profile_anchor,
        ),
    }
}

fn reconcile_existing_journal_destination(
    store: &RedbInstallationTransactionStore,
    journal: &SourceBundlePublicationJournal,
    precommit_files: Vec<MaterializedRolePrecommitReceipt>,
    selected_profile_anchor: &SelectedProfileAnchor<'_>,
) -> Result<CanarySourceBundleMaterializeOutcome, MaterializeError> {
    match reconcile_journal_destination(journal, selected_profile_anchor) {
        Ok(Some(receipt)) => {
            let updated = SourceBundlePublicationJournal {
                state: SourceBundlePublicationJournalState::Published,
                destination_identity: Some(receipt.directory_publication.destination_identity),
                directory_receipt: Some(receipt.directory_publication.clone()),
                diagnostic: None,
                ..journal.clone()
            };
            selected_profile_anchor.revalidate()?;
            let recorded = match store.record_source_bundle_publication(&updated) {
                Ok(recorded) => recorded,
                Err(error) if journal.state == SourceBundlePublicationJournalState::Intent => {
                    return persist_unknown_publication(
                        store,
                        journal,
                        precommit_files,
                        format!(
                            "reconciled destination failed durable authority verification: {error}"
                        ),
                        selected_profile_anchor,
                    );
                }
                Err(error) => {
                    return Ok(journal_unknown_outcome(
                        journal,
                        precommit_files,
                        format!(
                            "unknown destination failed durable authority verification: {error}"
                        ),
                        selected_profile_anchor,
                    ));
                }
            };
            let receipt = load_verified_published_receipt(
                store,
                &recorded.operation_id,
                selected_profile_anchor,
            )?;
            Ok(CanarySourceBundleMaterializeOutcome::Published(receipt))
        }
        Ok(None) if journal.state == SourceBundlePublicationJournalState::Intent => {
            resume_intent_publication(store, journal, precommit_files, selected_profile_anchor)
        }
        Ok(None) => Ok(journal_unknown_outcome(
            journal,
            precommit_files,
            "durable publication journal exists but its destination is absent".to_owned(),
            selected_profile_anchor,
        )),
        Err(error) if journal.state == SourceBundlePublicationJournalState::Intent => {
            persist_unknown_publication(
                store,
                journal,
                precommit_files,
                format!("durable publication reconciliation rejected: {error}"),
                selected_profile_anchor,
            )
        }
        Err(error) => Ok(journal_unknown_outcome(
            journal,
            precommit_files,
            format!("durable publication reconciliation rejected: {error}"),
            selected_profile_anchor,
        )),
    }
}

fn reconcile_existing_publication(
    input: &CanarySourceBundleMaterializeInput,
    selection: &ProfileSelectionResolution,
    selected_profile_anchor: &SelectedProfileAnchor<'_>,
) -> Result<Option<CanarySourceBundleMaterializeOutcome>, MaterializeError> {
    validate_materializer_selection(input, selection)?;
    validate_absolute(&input.output_bundle, "output_bundle")?;
    validate_absolute(&input.store_path, "store_path")?;
    selected_profile_anchor.revalidate()?;
    let operation_id = source_bundle_publication_operation_id(
        &input.transaction_id,
        &input.output_bundle,
        &input.generation,
    )
    .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    match fs::symlink_metadata(&input.store_path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Err(MaterializeError::Invalid(
                "publication store path is not a regular file".to_owned(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(MaterializeError::Platform(error.to_string())),
    }
    let store = RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let Some(journal) = store
        .load_source_bundle_publication(&operation_id)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?
    else {
        return Ok(None);
    };
    if journal.transaction_id != input.transaction_id
        || journal.generation != input.generation
        || journal.profile_governed_roots != selection.roots
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(journal.selected_profile_anchor_path.as_str()),
            &selected_profile_anchor.canonical_path,
        )
        || journal.selected_profile_anchor_identity != selected_profile_anchor.identity
        || !eliot_platform_windows::windows_paths_equal(
            &journal.output_bundle,
            &input.output_bundle,
        )
    {
        return Err(MaterializeError::Invalid(
            "publication journal identity differs from the requested operation".to_owned(),
        ));
    }
    let precommit_files = precommit_from_journal(&journal.precommit_files);
    if journal.state == SourceBundlePublicationJournalState::Published {
        return Ok(Some(CanarySourceBundleMaterializeOutcome::Published(
            load_verified_published_receipt(&store, &operation_id, selected_profile_anchor)?,
        )));
    }
    Ok(Some(reconcile_existing_journal_destination(
        &store,
        &journal,
        precommit_files,
        selected_profile_anchor,
    )?))
}

#[allow(
    clippy::too_many_lines,
    reason = "publication keeps validation, immutable writes, readback and receipt binding together"
)]
#[cfg(test)]
fn materialize_with_executables(
    input: &CanarySourceBundleMaterializeInput,
    executables: &[ValidatedExecutable],
    stop_after_durable_intent: bool,
) -> Result<CanarySourceBundleMaterializeOutcome, MaterializeError> {
    let selection = GenerationPackagePlanner::resolve_profile_selection(&input.profile_selection)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let (anchor_identity, anchor_handle) = open_no_follow_directory(Path::new(
        input.profile_selection.profile_anchor_root.as_str(),
    ))
    .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    let selected_profile_anchor =
        SelectedProfileAnchor::retain(input, &selection, &anchor_handle, anchor_identity)?;
    materialize_with_resolved_selection(
        input,
        executables,
        stop_after_durable_intent,
        &selection,
        &selected_profile_anchor,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "publication keeps validation, immutable writes, readback and receipt binding together"
)]
fn materialize_with_resolved_selection(
    input: &CanarySourceBundleMaterializeInput,
    executables: &[ValidatedExecutable],
    stop_after_durable_intent: bool,
    selection: &ProfileSelectionResolution,
    selected_profile_anchor: &SelectedProfileAnchor<'_>,
) -> Result<CanarySourceBundleMaterializeOutcome, MaterializeError> {
    validate_role_inventory(&REQUIRED_ROLES)?;
    validate_absolute(&input.output_bundle, "output_bundle")?;
    validate_absolute(
        Path::new(input.profile_selection.profile_anchor_root.as_str()),
        "profile_anchor_root",
    )?;
    validate_absolute(
        Path::new(input.profile_selection.staging_root.as_str()),
        "staging_root",
    )?;
    validate_absolute(&input.store_path, "store_path")?;
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
    if executables.len() != 12 {
        return Err(MaterializeError::Invalid(
            "exactly twelve validated executables are required".to_owned(),
        ));
    }

    validate_materializer_selection(input, selection)?;
    selected_profile_anchor.revalidate()?;
    let typed =
        build_typed_bundle_with_selection(input, executables, selection, selected_profile_anchor)?;
    selected_profile_anchor.revalidate()?;
    let publication = OwnedDirectoryPublication::create(&input.output_bundle)
        .map_err(|error| MaterializeError::Platform(error.to_string()))?;
    selected_profile_anchor.revalidate()?;
    let temp = publication.temporary_path().to_path_buf();
    let mut source_identities = BTreeMap::<String, FileIdentity>::new();
    for (role, executable) in REQUIRED_ROLES {
        let bytes = role_bytes(role, executables, &typed.json_roles)?;
        let destination = temp.join(role);
        selected_profile_anchor.revalidate()?;
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
    selected_profile_anchor.revalidate()?;
    sync_directory(&temp).map_err(|error| MaterializeError::RecoveryRequired {
        operation: input.transaction_id.as_str().to_owned(),
        stage: InstallationRecoveryStage::ParentSync,
        source_context: temp.to_string_lossy().into_owned(),
        cleanup: Some(format!(
            "temporary publication retained for exact recovery after sync failure: {error}"
        )),
    })?;

    let precommit_bundle = publication.trusted_source_bundle().map_err(|error| {
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

    let operation_id = source_bundle_publication_operation_id(
        &input.transaction_id,
        &input.output_bundle,
        &input.generation,
    )
    .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    let precommit_digest = sha256_hex(
        &serde_json::to_vec(&precommit_files)
            .map_err(|error| MaterializeError::Contract(error.to_string()))?,
    );
    let journal_precommit_files = journal_roles_from_precommit(&precommit_files)?;
    let journal_intent = SourceBundlePublicationJournal {
        wire_version: SOURCE_BUNDLE_PUBLICATION_JOURNAL_WIRE_VERSION,
        operation_id,
        transaction_id: input.transaction_id.clone(),
        output_bundle: input.output_bundle.clone(),
        temporary_path: publication.temporary_path().to_path_buf(),
        temporary_name: publication.temporary_name().to_owned(),
        parent_identity: publication.parent_identity(),
        generation: input.generation.clone(),
        profile_governed_roots: typed.profile_governed_roots.clone(),
        selected_profile_anchor_path: PlatformHandle::new(selected_profile_anchor.path_string())
            .map_err(|error| {
                MaterializeError::Contract(format!("selected profile anchor path: {error}"))
            })?,
        selected_profile_anchor_identity: selected_profile_anchor.identity,
        manifest_digest: PlatformHandle::new(typed.manifest.canonical_digest())
            .map_err(|error| MaterializeError::Contract(error.to_string()))?,
        evidence_digest: typed.evidence_digest.clone(),
        precommit_digest: PlatformHandle::new(precommit_digest)
            .map_err(|error| MaterializeError::Contract(error.to_string()))?,
        precommit_files: journal_precommit_files,
        source_identity: precommit_directory_identity,
        state: SourceBundlePublicationJournalState::Intent,
        destination_identity: None,
        directory_receipt: None,
        diagnostic: None,
    };
    // The durable intent is the only authority allowed to reopen this exact
    // temporary object after a crash. Drop the creator handle before begin so
    // begin can independently reopen it with DELETE authority and verify the
    // complete journal-bound tree. The move is then performed by a second
    // exact identity-bound resume, never by an unjournaled creator handle.
    drop(publication);
    selected_profile_anchor.revalidate()?;
    let existing_journal =
        RedbInstallationTransactionStore::begin_source_bundle_publication_at_exact_path(
            &input.store_path,
            &journal_intent,
        )
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    if stop_after_durable_intent {
        return Err(MaterializeError::Platform(
            "injected process loss after durable publication Intent".to_owned(),
        ));
    }
    let store = RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path)
        .map_err(|error| MaterializeError::Contract(error.to_string()))?;
    match existing_journal.state {
        SourceBundlePublicationJournalState::Intent => resume_intent_publication(
            &store,
            &existing_journal,
            precommit_files,
            selected_profile_anchor,
        ),
        SourceBundlePublicationJournalState::Published => {
            let receipt = load_verified_published_receipt(
                &store,
                &existing_journal.operation_id,
                selected_profile_anchor,
            )?;
            Ok(CanarySourceBundleMaterializeOutcome::Published(receipt))
        }
        SourceBundlePublicationJournalState::CommittedUnknown => Ok(journal_unknown_outcome(
            &existing_journal,
            precommit_files,
            "durable publication journal requires exact destination reconciliation".to_owned(),
            selected_profile_anchor,
        )),
    }
}

/// Materialize one exact fifteen-role Phase-A source bundle.
#[cfg(all(test, windows))]
fn materialize_canary_source_bundle(
    input: &CanarySourceBundleMaterializeInput,
) -> Result<CanarySourceBundleMaterializeOutcome, InstallationError> {
    let (anchor_identity, anchor_handle) = open_no_follow_directory(Path::new(
        input.profile_selection.profile_anchor_root.as_str(),
    ))
    .map_err(|error| InstallationError::Platform(error.to_string()))?;
    materialize_canary_source_bundle_with_retained_profile_anchor(
        input,
        &anchor_handle,
        anchor_identity,
    )
}

/// Materialize one exact fifteen-role Phase-A source bundle while preserving
/// the selected profile-anchor object from the caller's pre-write selection
/// through reconciliation, staging, durable intent, and publication.
pub fn materialize_canary_source_bundle_with_retained_profile_anchor(
    input: &CanarySourceBundleMaterializeInput,
    selected_profile_anchor_handle: &File,
    selected_profile_anchor_identity: FileIdentity,
) -> Result<CanarySourceBundleMaterializeOutcome, InstallationError> {
    let selection = GenerationPackagePlanner::resolve_profile_selection(&input.profile_selection)?;
    validate_materializer_selection(input, &selection).map_err(to_installation_error)?;
    let selected_profile_anchor = SelectedProfileAnchor::retain(
        input,
        &selection,
        selected_profile_anchor_handle,
        selected_profile_anchor_identity,
    )
    .map_err(to_installation_error)?;
    if let Some(existing) =
        reconcile_existing_publication(input, &selection, &selected_profile_anchor)
            .map_err(to_installation_error)?
    {
        return Ok(existing);
    }
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
        (input.eliot_doctor_exe.clone(), "eliot-doctor.exe"),
        (input.eliot_testd_exe.clone(), "eliot-testd.exe"),
        (
            input.eliot_native_worker_exe.clone(),
            "eliot-native-worker.exe",
        ),
        (input.eliot_wasm_host_exe.clone(), "eliot-wasm-host.exe"),
        (input.eliot_user_broker_exe.clone(), "eliot-user-broker.exe"),
        (input.eliot_notify_exe.clone(), "eliot-notify.exe"),
    ];
    let executables = executable_inputs
        .into_iter()
        .map(|(path, role)| validate_executable(&path, role).map_err(to_installation_error))
        .collect::<Result<Vec<_>, _>>()?;
    materialize_with_resolved_selection(
        input,
        &executables,
        false,
        &selection,
        &selected_profile_anchor,
    )
    .map_err(to_installation_error)
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    use eliot_installation::{
        GenerationPackagePlanInput, InstallationTransactionStore, ProfileRootAnchors,
        RedbInstallationTransactionStore, validate_installation_transaction_json,
    };
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
            "eliot-doctor.exe",
            "eliot-testd.exe",
            "eliot-native-worker.exe",
            "eliot-wasm-host.exe",
            "eliot-user-broker.exe",
            "eliot-notify.exe",
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
                    signer_certificate_sha256: Some("a".repeat(64)),
                    signer_subject: Some("ELIOT test-support unsigned fixture".to_owned()),
                    signer_not_before_unix_seconds: Some(1),
                    signer_not_after_unix_seconds: Some(2),
                    verification_time_unix_seconds: Some(1),
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
        let output_bundle = source_parent.path().join("bundle");
        let staging_root = staging.path().join("staging");
        let profile_anchor_root = handle(anchor.path().to_string_lossy().into_owned());
        let local_app_data = handle(
            eliot_platform_windows::current_user_local_app_data_root()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        CanarySourceBundleMaterializeInput {
            eliot_host_exe: PathBuf::new(),
            eliot_watchdog_exe: PathBuf::new(),
            eliot_kernel_exe: PathBuf::new(),
            eliot_store_surreal_exe: PathBuf::new(),
            surreal_exe: PathBuf::new(),
            eliotd_exe: PathBuf::new(),
            eliot_doctor_exe: PathBuf::new(),
            eliot_testd_exe: PathBuf::new(),
            eliot_native_worker_exe: PathBuf::new(),
            eliot_wasm_host_exe: PathBuf::new(),
            eliot_user_broker_exe: PathBuf::new(),
            eliot_notify_exe: PathBuf::new(),
            agent_bridge_exe: None,
            agent_bridge_account: None,
            output_bundle: output_bundle.clone(),
            store_path: source_parent.path().join("transaction.redb"),
            generation: handle("generation-test"),
            installation_epoch: InstallationEpoch {
                installation: handle("installation-test"),
                lineage_id: handle("lineage-test"),
                sequence: 1,
            },
            profile_selection: ProfileSelectionInput {
                profile: InstallationProfile::PortableDev,
                anchors: ProfileRootAnchors {
                    program_files: None,
                    program_data: None,
                    local_app_data,
                    repository_root: Some(profile_anchor_root.clone()),
                },
                profile_anchor_root,
                installation_key: None,
                component: "eliot".to_owned(),
                version: "dev".to_owned(),
                generation: Some("generation-test".to_owned()),
                source_root: handle(output_bundle.to_string_lossy().into_owned()),
                staging_root: handle(staging_root.to_string_lossy().into_owned()),
            },
            transaction_id: handle("transaction:test"),
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
        let outcome = materialize_with_executables(&input, &fake_executables(), false).unwrap();
        let CanarySourceBundleMaterializeOutcome::Published(receipt) = outcome else {
            panic!("exact materializer publication unexpectedly requires reconciliation");
        };
        (source_parent, anchor, staging, input, receipt)
    }

    #[cfg(windows)]
    #[test]
    fn bridge_source_inputs_are_paired_and_legacy_none_is_preserved() {
        let source_parent = TempDir::new().unwrap();
        let anchor = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();
        let mut input = test_input(&source_parent, &anchor, &staging);
        assert_eq!(
            bridge_source_plan(&input, &"a".repeat(64), &"b".repeat(64)).unwrap(),
            None
        );

        input.agent_bridge_exe = Some(source_parent.path().join("eliot-agent-bridge.exe"));
        assert!(bridge_source_plan(&input, &"a".repeat(64), &"b".repeat(64)).is_err());
        input.agent_bridge_exe = None;
        input.agent_bridge_account = Some("ELIOT-ACCOUNT-DOES-NOT-EXIST-9D7C".to_owned());
        assert!(bridge_source_plan(&input, &"a".repeat(64), &"b".repeat(64)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn bridge_source_plan_rejects_observed_kernel_substitution() {
        let source_parent = TempDir::new().unwrap();
        let anchor = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();
        let mut input = test_input(&source_parent, &anchor, &staging);
        let bridge = source_parent.path().join("eliot-agent-bridge.exe");
        fs::write(&bridge, b"bridge-source").unwrap();
        input.agent_bridge_exe = Some(bridge);
        input.agent_bridge_account = Some("NT AUTHORITY\\LocalService".to_owned());
        let source = bridge_source_plan(&input, &"a".repeat(64), &"b".repeat(64)).unwrap();
        let source = source.expect("paired bridge source");
        assert_ne!(source.source_executable_sha256.as_str(), "a".repeat(64));
        assert!(
            bridge_source_plan(
                &input,
                source.source_executable_sha256.as_str(),
                &"b".repeat(64),
            )
            .is_err()
        );
    }

    #[cfg(windows)]
    fn crash_after_publication_intent(
        input: &CanarySourceBundleMaterializeInput,
    ) -> SourceBundlePublicationJournal {
        let error = materialize_with_executables(input, &fake_executables(), true).unwrap_err();
        assert!(error.to_string().contains("injected process loss"));
        let operation_id = source_bundle_publication_operation_id(
            &input.transaction_id,
            &input.output_bundle,
            &input.generation,
        )
        .unwrap();
        let store =
            RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path).unwrap();
        let journal = store
            .load_source_bundle_publication(&operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(journal.state, SourceBundlePublicationJournalState::Intent);
        assert!(journal.temporary_path.exists());
        assert!(!journal.output_bundle.exists());
        journal
    }

    #[cfg(windows)]
    fn bound_plan_input(
        input: &CanarySourceBundleMaterializeInput,
        output_bundle: &Path,
    ) -> GenerationPackagePlanInput {
        GenerationPackagePlanInput {
            transaction_id: input.transaction_id.clone(),
            installation_epoch: input.installation_epoch.clone(),
            profile: input.profile_selection.profile,
            profile_anchor_root: input.profile_selection.profile_anchor_root.clone(),
            installation_key: None,
            generation: input.generation.clone(),
            source_root: handle(output_bundle.to_string_lossy().into_owned()),
            staging_root: input.profile_selection.staging_root.clone(),
            minimum_store_available_bytes: 1,
            recovery_command: handle("eliot recover --transaction-id transaction:test"),
            agent_bridge_source: None,
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
        substituted[9] = ("authority.json", false);
        assert!(validate_role_inventory(&substituted).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn materializer_output_matches_real_planner_launch_template() {
        let source_parent = TempDir::new().unwrap();
        let anchor = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();
        let input = test_input(&source_parent, &anchor, &staging);
        let outcome = materialize_with_executables(&input, &fake_executables(), false).unwrap();
        let CanarySourceBundleMaterializeOutcome::Published(receipt) = outcome else {
            panic!("exact materializer publication unexpectedly requires reconciliation");
        };
        assert_eq!(receipt.files.len(), 14);
        assert_eq!(
            receipt.directory_publication.source_identity,
            receipt.directory_publication.destination_identity
        );
        let output_bundle = PathBuf::from(&receipt.bundle_path);
        let binding = receipt.planner_binding().unwrap();
        let transaction = GenerationPackagePlanner::plan_with_published_profile_binding(
            GenerationPackagePlanInput {
                transaction_id: input.transaction_id.clone(),
                installation_epoch: input.installation_epoch.clone(),
                profile: input.profile_selection.profile,
                profile_anchor_root: input.profile_selection.profile_anchor_root.clone(),
                installation_key: None,
                generation: input.generation.clone(),
                source_root: handle(output_bundle.to_string_lossy().into_owned()),
                staging_root: input.profile_selection.staging_root.clone(),
                minimum_store_available_bytes: 1,
                recovery_command: handle("eliot recover --transaction-id transaction:test"),
                agent_bridge_source: None,
            },
            &input.profile_selection,
            binding.profile_governed_roots,
            binding.source_identity,
            binding.files,
            binding.evidence_digest,
        )
        .expect("materialized bundle must feed the real planner");
        let config_bytes = fs::read(output_bundle.join("generation.json")).unwrap();
        let config: StoreLaunchConfig = serde_json::from_slice(&config_bytes).unwrap();
        let current_peer =
            eliot_platform_windows::current_process_named_pipe_expectation().unwrap();
        assert_eq!(
            config.expected_client_sid,
            current_peer.expected_sid(),
            "Store peer binding must match the selected current-user token"
        );
        assert_eq!(
            config.expected_client_session_id,
            current_peer.expected_session_id(),
            "Store peer session must match the selected current-user token"
        );
        let governor_bytes = fs::read(output_bundle.join("eliotd-governor.json")).unwrap();
        let governor: GovernorLaunchConfig = serde_json::from_slice(&governor_bytes).unwrap();
        assert_eq!(
            governor.kernel.principal,
            current_peer.expected_sid(),
            "Governor Kernel principal must match the selected current-user token"
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
    fn crash_after_intent_resumes_the_recorded_temporary_without_original_sources() {
        let source_parent = TempDir::new().unwrap();
        let anchor = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();
        let input = test_input(&source_parent, &anchor, &staging);
        let journal = crash_after_publication_intent(&input);
        for source in [
            &input.eliot_host_exe,
            &input.eliot_watchdog_exe,
            &input.eliot_kernel_exe,
            &input.eliot_store_surreal_exe,
            &input.surreal_exe,
            &input.eliotd_exe,
            &input.eliot_doctor_exe,
            &input.eliot_testd_exe,
            &input.eliot_native_worker_exe,
            &input.eliot_wasm_host_exe,
        ] {
            assert!(
                !source.exists(),
                "fixture original source must be unavailable"
            );
        }

        let outcome = materialize_canary_source_bundle(&input).unwrap();
        let CanarySourceBundleMaterializeOutcome::Published(receipt) = outcome else {
            panic!("recorded temporary publication was not resumed");
        };
        assert_eq!(receipt.source_identity, journal.source_identity);
        assert_eq!(
            receipt.directory_publication.destination_identity,
            journal.source_identity
        );
        assert!(!journal.temporary_path.exists());
        assert!(journal.output_bundle.exists());
        let store =
            RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path).unwrap();
        assert_eq!(
            store
                .load_source_bundle_publication(&journal.operation_id)
                .unwrap()
                .unwrap()
                .state,
            SourceBundlePublicationJournalState::Published
        );
    }

    #[cfg(windows)]
    #[test]
    fn missing_or_substituted_recorded_temporary_is_durably_unknown_and_never_resent() {
        for substituted in [false, true] {
            let source_parent = TempDir::new().unwrap();
            let anchor = TempDir::new().unwrap();
            let staging = TempDir::new().unwrap();
            let input = test_input(&source_parent, &anchor, &staging);
            let journal = crash_after_publication_intent(&input);
            fs::remove_dir_all(&journal.temporary_path).unwrap();
            if substituted {
                fs::create_dir(&journal.temporary_path).unwrap();
                fs::write(journal.temporary_path.join("foreign.txt"), b"foreign").unwrap();
            }

            let first = materialize_canary_source_bundle(&input).unwrap();
            assert!(matches!(
                first,
                CanarySourceBundleMaterializeOutcome::CommittedUnknown(_)
            ));
            assert!(!journal.output_bundle.exists());
            let store =
                RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path)
                    .unwrap();
            assert_eq!(
                store
                    .load_source_bundle_publication(&journal.operation_id)
                    .unwrap()
                    .unwrap()
                    .state,
                SourceBundlePublicationJournalState::CommittedUnknown
            );
            drop(store);

            let second = materialize_canary_source_bundle(&input).unwrap();
            assert!(matches!(
                second,
                CanarySourceBundleMaterializeOutcome::CommittedUnknown(_)
            ));
            assert!(!journal.output_bundle.exists());
            let temporary_count = fs::read_dir(source_parent.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".bundle.tmp.")
                })
                .count();
            assert_eq!(temporary_count, usize::from(substituted));
        }
    }

    #[cfg(windows)]
    #[test]
    fn rejected_destination_reconciliation_is_durably_unknown() {
        let source_parent = TempDir::new().unwrap();
        let anchor = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();
        let input = test_input(&source_parent, &anchor, &staging);
        let journal = crash_after_publication_intent(&input);
        fs::create_dir(&journal.output_bundle).unwrap();
        fs::write(journal.output_bundle.join("foreign.txt"), b"foreign").unwrap();

        let outcome = materialize_canary_source_bundle(&input).unwrap();
        assert!(matches!(
            outcome,
            CanarySourceBundleMaterializeOutcome::CommittedUnknown(_)
        ));
        let store =
            RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path).unwrap();
        let recorded = store
            .load_source_bundle_publication(&journal.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            recorded.state,
            SourceBundlePublicationJournalState::CommittedUnknown
        );
        assert!(
            recorded
                .diagnostic
                .as_deref()
                .is_some_and(|diagnostic| diagnostic.contains("reconciliation rejected"))
        );
        assert!(journal.temporary_path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn response_loss_destination_reconciliation_promotes_the_same_operation() {
        let source_parent = TempDir::new().unwrap();
        let anchor = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();
        let input = test_input(&source_parent, &anchor, &staging);
        let journal = crash_after_publication_intent(&input);
        let store =
            RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path).unwrap();
        let unknown = SourceBundlePublicationJournal {
            state: SourceBundlePublicationJournalState::CommittedUnknown,
            destination_identity: None,
            directory_receipt: None,
            diagnostic: Some("injected response loss".to_owned()),
            ..journal.clone()
        };
        store.record_source_bundle_publication(&unknown).unwrap();
        let publication = OwnedDirectoryPublication::resume(
            &journal.output_bundle,
            &journal.temporary_path,
            &journal.temporary_name,
            journal.parent_identity,
            journal.source_identity,
        )
        .unwrap();
        assert!(matches!(
            publication.publish(journal.source_identity).unwrap(),
            DirectoryPublicationOutcome::Published(_)
        ));
        drop(store);

        let outcome = materialize_canary_source_bundle(&input).unwrap();
        assert!(matches!(
            outcome,
            CanarySourceBundleMaterializeOutcome::Published(_)
        ));
        let store =
            RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path).unwrap();
        let recovered = store
            .load_source_bundle_publication(&journal.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            recovered.state,
            SourceBundlePublicationJournalState::Published
        );
        assert_eq!(recovered.operation_id, journal.operation_id);
        assert_eq!(recovered.source_identity, journal.source_identity);
    }

    #[cfg(windows)]
    #[test]
    fn existing_published_forged_valid_authenticode_is_not_materialized() {
        let (_source_parent, _anchor, _staging, input, _receipt) = materialized_fixture();
        let operation_id = source_bundle_publication_operation_id(
            &input.transaction_id,
            &input.output_bundle,
            &input.generation,
        )
        .unwrap();
        let store =
            RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path).unwrap();
        store
            .corrupt_source_bundle_authenticode_fixture(&operation_id)
            .unwrap();
        drop(store);

        let error = materialize_canary_source_bundle(&input)
            .expect_err("forged stale Valid evidence must not materialize");
        assert!(
            error.to_string().contains("Authenticode readback")
                || error
                    .to_string()
                    .contains("installation transaction identity conflict"),
            "the sealed WinTrust verifier must reject forged stale evidence: {error}"
        );
        let store =
            RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path).unwrap();
        let recorded = store
            .load_source_bundle_publication(&operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            recorded.state,
            SourceBundlePublicationJournalState::Published
        );
        assert_eq!(
            recorded.precommit_files[0]
                .authenticode
                .as_ref()
                .and_then(|evidence| evidence.signer_subject.as_deref()),
            Some("ELIOT forged stale Valid fixture")
        );
    }

    #[cfg(windows)]
    #[test]
    fn response_loss_with_stale_authenticode_is_durably_unknown() {
        let source_parent = TempDir::new().unwrap();
        let anchor = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();
        let input = test_input(&source_parent, &anchor, &staging);
        let journal = crash_after_publication_intent(&input);
        let store =
            RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path).unwrap();
        store
            .corrupt_source_bundle_authenticode_fixture(&journal.operation_id)
            .unwrap();
        drop(store);
        let publication = OwnedDirectoryPublication::resume(
            &journal.output_bundle,
            &journal.temporary_path,
            &journal.temporary_name,
            journal.parent_identity,
            journal.source_identity,
        )
        .unwrap();
        assert!(matches!(
            publication.publish(journal.source_identity).unwrap(),
            DirectoryPublicationOutcome::Published(_)
        ));

        let outcome = materialize_canary_source_bundle(&input).unwrap();
        assert!(matches!(
            outcome,
            CanarySourceBundleMaterializeOutcome::CommittedUnknown(_)
        ));
        let store =
            RedbInstallationTransactionStore::open_existing_exact_path(&input.store_path).unwrap();
        let recorded = store
            .load_source_bundle_publication(&journal.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            recorded.state,
            SourceBundlePublicationJournalState::CommittedUnknown
        );
        assert!(
            recorded
                .diagnostic
                .as_deref()
                .is_some_and(|diagnostic| diagnostic.contains("authority verification"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn bound_generation_writes_exact_output_and_store_paths() {
        let (source_parent, _anchor, _staging, input, receipt) = materialized_fixture();
        let output_bundle = PathBuf::from(&receipt.bundle_path);
        let output = source_parent.path().join("generated.json");
        let store = source_parent.path().join("transaction.redb");
        let transaction_id = input.transaction_id.clone();
        let binding = receipt.planner_binding().unwrap();

        let outcome = crate::run_installation_generate_with_output_writer(
            bound_plan_input(&input, &output_bundle),
            output.clone(),
            store.clone(),
            binding,
            input.profile_selection.clone(),
            crate::write_transaction_artifact,
        )
        .unwrap();

        match outcome {
            crate::InstallationGenerationOutcome::Generated {
                transaction_id: generated_transaction_id,
                output_path,
                store_path,
            } => {
                assert_eq!(generated_transaction_id, transaction_id);
                assert_eq!(output_path, output);
                assert_eq!(store_path, store);
            }
            other => panic!("bound generation unexpectedly returned {other:?}"),
        }
        assert!(
            output.exists(),
            "bound generation omitted exact JSON output"
        );
        assert!(
            store.exists(),
            "bound generation omitted exact durable store"
        );
        let output_bytes = fs::read(&output).unwrap();
        assert_eq!(output_bytes.last(), Some(&b'\n'));
        validate_installation_transaction_json(&output_bytes).unwrap();
        let diagnostic: serde_json::Value = serde_json::from_slice(&output_bytes).unwrap();
        let durable_store =
            RedbInstallationTransactionStore::open_existing_exact_path(&store).unwrap();
        let durable = durable_store.load(&transaction_id).unwrap().unwrap();
        assert_eq!(diagnostic, serde_json::to_value(&durable).unwrap());
        let generation_path = output_bundle.join("generation.json");
        let mut substituted = fs::read(&generation_path).unwrap();
        substituted.push(b' ');
        fs::write(&generation_path, substituted).unwrap();
        assert!(matches!(
            durable_store.load(&transaction_id),
            Err(InstallationError::IdentityConflict)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn partial_output_failure_returns_unknown_and_store_remains_sole_authority() {
        let (source_parent, _anchor, _staging, input, receipt) = materialized_fixture();
        let output_bundle = PathBuf::from(&receipt.bundle_path);
        let output = source_parent.path().join("generated.json");
        let store = source_parent.path().join("transaction.redb");
        let transaction_id = input.transaction_id.clone();
        let binding = receipt.planner_binding().unwrap();

        let outcome = crate::run_installation_generate_with_output_writer(
            bound_plan_input(&input, &output_bundle),
            output.clone(),
            store.clone(),
            binding,
            input.profile_selection.clone(),
            |path, _transaction| {
                fs::write(path, b"{\"partial\":")?;
                Err(std::io::Error::other("injected output failure"))
            },
        )
        .unwrap();

        match outcome {
            crate::InstallationGenerationOutcome::OutputReconciliationRequired(reconciliation) => {
                assert_eq!(reconciliation.transaction_id, transaction_id);
                assert_eq!(reconciliation.store_path, store);
                assert_eq!(reconciliation.output_path, output);
                assert!(
                    reconciliation
                        .diagnostic
                        .contains("injected output failure")
                );
            }
            other => panic!("output failure unexpectedly returned {other:?}"),
        }
        assert!(
            store.exists(),
            "durable store was removed after output failure"
        );
        assert_eq!(fs::read(&output).unwrap(), b"{\"partial\":");
        assert!(validate_installation_transaction_json(&fs::read(&output).unwrap()).is_err());
        let durable_store =
            RedbInstallationTransactionStore::open_existing_exact_path(&store).unwrap();
        assert!(durable_store.load(&transaction_id).unwrap().is_some());
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
    fn planner_rejects_rehashed_noncanonical_generation_target() {
        let (_source_parent, _anchor, _staging, input, receipt) = materialized_fixture();
        let bundle = PathBuf::from(&receipt.bundle_path);
        let generation_path = bundle.join("generation.json");
        let mut config: StoreLaunchConfig =
            serde_json::from_slice(&fs::read(&generation_path).unwrap()).unwrap();
        config.namespace = "other".to_owned();
        config.approved_config_hash = launch_config_digest(&config).unwrap();
        fs::write(&generation_path, serde_json::to_vec(&config).unwrap()).unwrap();

        let source = TrustedSourceBundle::open(&bundle).unwrap();
        let observed = source.observe().unwrap();
        let expected = REQUIRED_ROLES
            .iter()
            .map(|(role, _)| {
                let file = observed
                    .files
                    .iter()
                    .find(|file| file.relative_path == *role)
                    .unwrap();
                PackageArtifactDigest {
                    relative_path: role.to_string(),
                    expected_size: file.size,
                    sha256: handle(file.sha256.clone()),
                }
            })
            .collect::<Vec<_>>();
        let specs = REQUIRED_ROLES
            .iter()
            .map(|(role, executable)| {
                let file = expected
                    .iter()
                    .find(|file| file.relative_path == *role)
                    .unwrap();
                PackageFileSpec::new(role, *executable, file.expected_size).unwrap()
            })
            .collect::<Vec<_>>();
        let manifest = PackageManifest::new(input.generation.as_str(), specs).unwrap();
        let evidence =
            GenerationPackagePlanner::artifact_set_evidence_digest(&manifest, &expected).unwrap();
        let result = GenerationPackagePlanner::plan_with_source_publication_binding(
            bound_plan_input(&input, &bundle),
            source.identity(),
            expected,
            evidence,
        );
        assert!(
            result.is_err(),
            "rehashed noncanonical Store target must fail closed"
        );
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
        let error = materialize_with_executables(&input, &fake_executables(), false).unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(
            fs::read(input.output_bundle.join("owner.txt")).unwrap(),
            b"existing"
        );
        input.output_bundle = source_parent.path().join("different-bundle");
        assert!(!input.output_bundle.exists());
    }

    #[cfg(windows)]
    #[test]
    fn retained_publication_root_blocks_rename_during_role_writes() {
        let parent = TempDir::new().unwrap();
        let destination = parent.path().join("bundle");
        let publication = OwnedDirectoryPublication::create(&destination).unwrap();
        let temporary = publication.temporary_path().to_path_buf();
        let role = temporary.join("generation.json");
        write_create_new(&role, b"{\"diagnostic\":true}\n").unwrap();

        let substituted = parent.path().join("substituted");
        assert!(
            fs::rename(&temporary, &substituted).is_err(),
            "retained native root handle must block root substitution during writes"
        );
        assert_eq!(fs::read(role).unwrap(), b"{\"diagnostic\":true}\n");

        drop(publication);
        fs::remove_dir_all(temporary).unwrap();
    }
}
