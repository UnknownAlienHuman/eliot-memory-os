//! P-08: governed installation, discovery and update transaction contracts.
//!
//! This crate owns installation policy and durable decision state. Platform
//! adapters perform bounded effects through [`InstallationEffectPort`]; they
//! never decide admission, infer success from a path, or turn an unknown
//! external outcome into success. Canonical memory is not used as installer
//! control state.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

use eliot_contracts::{
    ContractIdentity, ContractVersion, contract_identity as make_contract_identity,
};
use eliot_platform::{
    InstallationObservation, InstallationPort, InstallationRequest, PlatformHandle, PortError,
    PortOutcome,
};
use eliot_platform_windows::{
    ProtectedPathLease, UserOwnedPathLease, require_protected_program_data_path,
};
use redb::{Database, ReadableDatabase, TableDefinition};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Stable wire name for the installation contract.
pub const CONTRACT_NAME: &str = "eliot.kernel.installation";
/// Current installation contract revision.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Returns the stable contract identity for handshakes and provenance.
pub fn contract_identity() -> Result<ContractIdentity, InstallationError> {
    #[derive(Serialize)]
    struct Shape {
        surface: &'static str,
        version: ContractVersion,
        transaction_rule: &'static str,
        unknown_rule: &'static str,
    }

    make_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &Shape {
            surface: "profile_catalogue_managed_change_transaction",
            version: CONTRACT_VERSION,
            transaction_rule: "immutable_plan_observed_stage_transition",
            unknown_rule: "rollback_required_until_reconciled",
        },
    )
    .map_err(|_| InstallationError::InvalidField {
        field: "contract_identity".to_owned(),
        reason: "canonical contract shape could not be serialized".to_owned(),
    })
}

/// Typed installation failures. No variant carries secrets or raw provider output.
#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationError {
    /// A required field is blank, malformed or out of bounds.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Field path rejected by installation validation.
        field: String,
        /// Stable reason for rejecting the field.
        reason: String,
    },
    /// A collection contains the same identity more than once.
    #[error("{kind} contains duplicate identity {identity}")]
    Duplicate {
        /// Collection or identity kind containing a duplicate.
        kind: String,
        /// Duplicate stable identity.
        identity: String,
    },
    /// A state transition is not admitted by the transaction machine.
    #[error("illegal installation transition from {from:?} to {to:?}")]
    IllegalTransition {
        /// Current transaction stage.
        from: InstallationStage,
        /// Requested transaction stage.
        to: InstallationStage,
    },
    /// A caller attempted to use a request for another transaction.
    #[error("installation transaction identity conflict")]
    IdentityConflict,
    /// A provider changed an external object without a durable acknowledgement.
    #[error("installation effect outcome is unknown at stage {stage:?}")]
    UnknownOutcome {
        /// Stage at which the provider outcome became unknown.
        stage: InstallationStage,
    },
    /// A known observation does not prove the requested postcondition.
    #[error("installation postcondition is incomplete: {0}")]
    IncompleteObservation(String),
    /// The selected profile and roots violate isolation policy.
    #[error("installation profile violation: {0}")]
    ProfileViolation(String),
    /// The platform contract rejected the request.
    #[error("platform contract: {0}")]
    Platform(String),
}

fn text(value: &str, field: &str) -> Result<(), InstallationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must be non-blank and free of control characters".to_owned(),
        });
    }
    if value.len() > 4096 {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must not exceed 4096 UTF-8 bytes".to_owned(),
        });
    }
    Ok(())
}

fn handle(value: &PlatformHandle, field: &str) -> Result<(), InstallationError> {
    text(value.as_str(), field)
}

fn sha256_handle(value: &PlatformHandle, field: &str) -> Result<(), InstallationError> {
    handle(value, field)?;
    if value.as_str().len() != 64
        || !value
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must be a lowercase SHA-256 digest".to_owned(),
        });
    }
    Ok(())
}

fn approved_path(value: &PlatformHandle, field: &str) -> Result<(), InstallationError> {
    handle(value, field)?;
    let path = Path::new(value.as_str());
    if !path.is_absolute() {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must be an absolute canonical path".to_owned(),
        });
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must not contain parent-directory traversal".to_owned(),
        });
    }
    Ok(())
}

fn approved_filename(
    value: &PlatformHandle,
    expected: &str,
    field: &str,
) -> Result<(), InstallationError> {
    if Path::new(value.as_str())
        .file_name()
        .and_then(|name| name.to_str())
        != Some(expected)
    {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: format!("must select the approved {expected} filename"),
        });
    }
    Ok(())
}

const MAX_VERIFIED_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Opens one installation-owned file through the protected no-follow lease,
/// hashes bytes from that retained handle, and verifies the approved digest.
///
/// The returned path is only a locator. Callers that need replacement
/// protection across a launch boundary must retain their own
/// [`ProtectedPathLease`] and use [`verify_file_digest_with_lease`].
pub fn verify_file_digest(
    path: impl AsRef<Path>,
    expected: &PlatformHandle,
    field: &str,
) -> Result<std::path::PathBuf, InstallationError> {
    let lease = ProtectedPathLease::open_existing_absolute(path.as_ref()).map_err(|error| {
        InstallationError::Platform(format!("{field}: protected file open failed: {error}"))
    })?;
    verify_file_digest_with_lease(&lease, expected, field)?;
    Ok(lease.path().to_path_buf())
}

/// Verifies bytes from an already-retained protected file handle.  No path
/// open occurs during hashing, so the caller can keep the same identity pinned
/// through a suspended process resume boundary.
pub fn verify_file_digest_with_lease(
    lease: &ProtectedPathLease,
    expected: &PlatformHandle,
    field: &str,
) -> Result<(), InstallationError> {
    sha256_handle(expected, field)?;
    lease
        .verify_stable_identity()
        .map_err(|error| InstallationError::Platform(format!("{field}: {error}")))?;
    lease
        .verify_path_identity()
        .map_err(|error| InstallationError::Platform(format!("{field}: {error}")))?;
    let bytes = lease
        .read_bounded(MAX_VERIFIED_FILE_BYTES)
        .map_err(|error| InstallationError::Platform(format!("{field}: {error}")))?;
    let digest = Sha256::digest(&bytes);
    let actual = format!("{digest:x}");
    if actual != expected.as_str() {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: format!("content digest mismatch (actual {actual})"),
        });
    }
    Ok(())
}

/// Verifies bytes from a retained portable-dev file lease.
pub fn verify_file_digest_with_user_lease(
    lease: &UserOwnedPathLease,
    expected: &PlatformHandle,
    field: &str,
) -> Result<(), InstallationError> {
    sha256_handle(expected, field)?;
    lease
        .verify_stable_identity()
        .and_then(|()| lease.verify_path_identity())
        .map_err(|error| InstallationError::Platform(format!("{field}: {error}")))?;
    let bytes = lease
        .read_bounded(MAX_VERIFIED_FILE_BYTES)
        .map_err(|error| InstallationError::Platform(format!("{field}: {error}")))?;
    let digest = Sha256::digest(&bytes);
    let actual = format!("{digest:x}");
    if actual != expected.as_str() {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: format!("content digest mismatch (actual {actual})"),
        });
    }
    Ok(())
}

/// Verifies that a caller-supplied locator resolves to the exact canonical
/// path recorded by the installation-owned candidate manifest.
pub fn verify_approved_path(
    path: impl AsRef<Path>,
    approved: &PlatformHandle,
    field: &str,
) -> Result<std::path::PathBuf, InstallationError> {
    handle(approved, field)?;
    let approved_path = Path::new(approved.as_str());
    let candidate_path = path.as_ref();
    if !approved_path.is_absolute() || !candidate_path.is_absolute() {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "approved and supplied paths must be absolute".to_owned(),
        });
    }
    let approved_lease = ProtectedPathLease::open_existing_absolute(approved_path)
        .map_err(|error| InstallationError::Platform(format!("{field} approved: {error}")))?;
    let candidate_lease = ProtectedPathLease::open_existing_absolute(candidate_path)
        .map_err(|error| InstallationError::Platform(format!("{field} supplied: {error}")))?;
    approved_lease
        .verify_stable_identity()
        .and_then(|()| approved_lease.verify_path_identity())
        .map_err(|error| InstallationError::Platform(format!("{field} approved: {error}")))?;
    candidate_lease
        .verify_stable_identity()
        .and_then(|()| candidate_lease.verify_path_identity())
        .map_err(|error| InstallationError::Platform(format!("{field} supplied: {error}")))?;
    if candidate_lease.path() != approved_lease.path()
        || candidate_lease.identity() != approved_lease.identity()
    {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "supplied path is not the approved canonical path".to_owned(),
        });
    }
    Ok(approved_lease.path().to_path_buf())
}

fn handles(
    values: &[PlatformHandle],
    field: &str,
    required: bool,
) -> Result<(), InstallationError> {
    if required && values.is_empty() {
        return Err(InstallationError::InvalidField {
            field: field.to_owned(),
            reason: "must not be empty".to_owned(),
        });
    }
    let mut seen = BTreeSet::new();
    for value in values {
        handle(value, field)?;
        if !seen.insert(value.as_str()) {
            return Err(InstallationError::Duplicate {
                kind: field.to_owned(),
                identity: value.as_str().to_owned(),
            });
        }
    }
    Ok(())
}

/// The supported installation supervision and path profiles.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationProfile {
    /// Elevated SCM-owned service with the strongest isolation guarantees.
    SystemService,
    /// Per-user installation supervised by the current user.
    UserMode,
    /// Repository-local disposable development profile.
    PortableDev,
}

impl InstallationProfile {
    /// Whether this profile requires administrative installation authority.
    #[must_use]
    pub const fn requires_admin(self) -> bool {
        matches!(self, Self::SystemService)
    }

    /// Whether this profile is permitted to share state with production roots.
    #[must_use]
    pub const fn is_disposable(self) -> bool {
        matches!(self, Self::PortableDev)
    }
}

/// The three roots whose ownership and mutability are kept separate.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationRoots {
    /// Immutable, versioned binaries and component artifacts.
    pub immutable_binaries: String,
    /// Durable service/installation state.
    pub durable_data: String,
    /// User configuration and cache.
    pub user_config_cache: String,
}

impl InstallationRoots {
    /// Creates and validates a root set for one profile.
    pub fn new(
        profile: InstallationProfile,
        immutable_binaries: impl Into<String>,
        durable_data: impl Into<String>,
        user_config_cache: impl Into<String>,
    ) -> Result<Self, InstallationError> {
        let roots = Self {
            immutable_binaries: immutable_binaries.into(),
            durable_data: durable_data.into(),
            user_config_cache: user_config_cache.into(),
        };
        roots.validate(profile)?;
        Ok(roots)
    }

    /// Validates path separation and rejects traversal or empty roots.
    pub fn validate(&self, profile: InstallationProfile) -> Result<(), InstallationError> {
        let values = [
            (&self.immutable_binaries, "immutable_binaries"),
            (&self.durable_data, "durable_data"),
            (&self.user_config_cache, "user_config_cache"),
        ];
        let mut identities = BTreeSet::new();
        for (value, field) in values {
            text(value, field)?;
            let normalized = value
                .replace('\\', "/")
                .trim_end_matches('/')
                .to_ascii_lowercase();
            if normalized == "."
                || normalized == ".."
                || normalized.starts_with("../")
                || normalized.contains("/../")
                || normalized.ends_with("/..")
            {
                return Err(InstallationError::ProfileViolation(
                    "installation roots must not contain parent traversal".to_owned(),
                ));
            }
            if !identities.insert(normalized) {
                return Err(InstallationError::ProfileViolation(
                    "immutable, durable and user roots must be distinct".to_owned(),
                ));
            }
        }
        if !profile.is_disposable()
            && self
                .immutable_binaries
                .eq_ignore_ascii_case(&self.durable_data)
        {
            return Err(InstallationError::ProfileViolation(
                "production binaries may not share the durable data root".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One installation lineage; sequence is monotonic only within this lineage.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct InstallationEpoch {
    /// Installation identity.
    pub installation: PlatformHandle,
    /// Stable lineage identity; it changes after restore or reconstitution.
    pub lineage_id: PlatformHandle,
    /// Monotonic sequence within the lineage.
    pub sequence: u64,
}

impl InstallationEpoch {
    /// Validates an installation epoch.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.installation, "installation_epoch.installation")?;
        handle(&self.lineage_id, "installation_epoch.lineage_id")?;
        if self.sequence == 0 {
            return Err(InstallationError::InvalidField {
                field: "installation_epoch.sequence".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        Ok(())
    }
}

/// The governed operation requested by a human/control-plane caller.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEnvironmentAction {
    /// Install an absent candidate.
    Install,
    /// Replace an active generation side-by-side.
    Update,
    /// Re-apply or repair a known installation.
    Repair,
    /// Remove registrations and immutable artifacts while preserving data by default.
    Remove,
    /// Register an already observed external integration.
    Register,
    /// Change an installation configuration without changing its artifact generation.
    Reconfigure,
}

/// A bounded, evidence-linked request to change the managed environment.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedEnvironmentChangeRequest {
    /// Stable request identity.
    pub request_id: PlatformHandle,
    /// Principal/reason reference; never a secret.
    pub requester_and_reason: PlatformHandle,
    /// Requested operation.
    pub action: ManagedEnvironmentAction,
    /// Catalogue family being changed.
    pub target_family: PlatformHandle,
    /// Exact candidate identity or generation.
    pub exact_candidate: PlatformHandle,
    /// Expected capability/problem delta.
    pub expected_delta: PlatformHandle,
    /// Source, license and dependency-closure evidence.
    pub source_assurance_refs: Vec<PlatformHandle>,
    /// Affected routes, modules, scopes and credential references.
    pub affected_refs: Vec<PlatformHandle>,
    /// Impact classification owned by the caller's governance policy.
    pub impact_class: PlatformHandle,
    /// Required owner for admission.
    pub required_owner: PlatformHandle,
    /// Backup, rollback or forward-repair plan reference.
    pub rollback_plan: PlatformHandle,
    /// Post-change verifier reference.
    pub verifier: PlatformHandle,
    /// Resource/budget policy reference.
    pub budget: PlatformHandle,
    /// Explicit stop condition.
    pub stop_condition: PlatformHandle,
}

impl ManagedEnvironmentChangeRequest {
    /// Validates the request without performing an external effect.
    pub fn validate(&self) -> Result<(), InstallationError> {
        for (value, field) in [
            (&self.request_id, "request_id"),
            (&self.requester_and_reason, "requester_and_reason"),
            (&self.target_family, "target_family"),
            (&self.exact_candidate, "exact_candidate"),
            (&self.expected_delta, "expected_delta"),
            (&self.impact_class, "impact_class"),
            (&self.required_owner, "required_owner"),
            (&self.rollback_plan, "rollback_plan"),
            (&self.verifier, "verifier"),
            (&self.budget, "budget"),
            (&self.stop_condition, "stop_condition"),
        ] {
            handle(value, field)?;
        }
        handles(&self.source_assurance_refs, "source_assurance_refs", true)?;
        handles(&self.affected_refs, "affected_refs", false)
    }
}

/// Broad discovery family used by the catalogue; presence is not admission.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationCategory {
    /// Agent runtime, host or ACP/stdio surface.
    AgentRuntime,
    /// Editor or professional application host.
    EditorHost,
    /// Local model runtime.
    LocalModelRuntime,
    /// MCP server or bridge.
    McpServer,
    /// Code-intelligence provider.
    CodeIntelligence,
    /// Database or store runtime.
    Database,
    /// Compiler, language server or development toolchain.
    Toolchain,
    /// Package manager or installer surface.
    PackageManager,
    /// Browser or professional tool.
    BrowserProfessionalTool,
    /// Cloud CLI or remote integration.
    CloudCli,
}

/// One versioned, detection-first discovery recipe.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationDiscoveryCatalogueEntry {
    /// Stable family identity.
    pub family_id: PlatformHandle,
    /// Discovery category.
    pub category: IntegrationCategory,
    /// Platforms on which the recipe is valid.
    pub supported_platforms: Vec<PlatformHandle>,
    /// Known executable/config/manifest locations.
    pub known_locations: Vec<PlatformHandle>,
    /// Safe discovery or negative-capability probes.
    pub safe_probes: Vec<PlatformHandle>,
    /// Official install/update/remove surfaces.
    pub managed_surfaces: Vec<PlatformHandle>,
    /// Required execution identities or credential references.
    pub credential_refs: Vec<PlatformHandle>,
    /// License, supply-chain and privacy notes.
    pub assurance_refs: Vec<PlatformHandle>,
    /// Candidate adapter/bridge identities.
    pub adapter_candidates: Vec<PlatformHandle>,
    /// Evidence expiry in Unix milliseconds, if bounded.
    pub evidence_expiry_ms: Option<u64>,
}

impl IntegrationDiscoveryCatalogueEntry {
    /// Validates the recipe and requires at least one safe discovery surface.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.family_id, "family_id")?;
        handles(&self.supported_platforms, "supported_platforms", true)?;
        handles(&self.known_locations, "known_locations", true)?;
        handles(&self.safe_probes, "safe_probes", true)?;
        handles(&self.managed_surfaces, "managed_surfaces", false)?;
        handles(&self.credential_refs, "credential_refs", false)?;
        handles(&self.assurance_refs, "assurance_refs", true)?;
        handles(&self.adapter_candidates, "adapter_candidates", false)?;
        if self.evidence_expiry_ms == Some(0) {
            return Err(InstallationError::InvalidField {
                field: "evidence_expiry_ms".to_owned(),
                reason: "must be absent or positive".to_owned(),
            });
        }
        Ok(())
    }
}

/// Immutable ELIOT-owned discovery catalogue, not a capability registry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationDiscoveryCatalogue {
    /// Catalogue origin/provenance reference.
    pub origin: PlatformHandle,
    /// Monotonic catalogue revision.
    pub revision: u64,
    /// Versioned discovery recipes.
    pub entries: Vec<IntegrationDiscoveryCatalogueEntry>,
}

impl IntegrationDiscoveryCatalogue {
    /// Validates all entries and rejects duplicate family identities.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.origin, "catalogue.origin")?;
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "catalogue.revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            if !seen.insert(entry.family_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "catalogue family".to_owned(),
                    identity: entry.family_id.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Finds one exact family recipe after validating the catalogue.
    pub fn entry(
        &self,
        family_id: &PlatformHandle,
    ) -> Result<&IntegrationDiscoveryCatalogueEntry, InstallationError> {
        self.validate()?;
        self.entries
            .iter()
            .find(|entry| &entry.family_id == family_id)
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "catalogue family was not found".to_owned(),
                )
            })
    }
}

/// Exact immutable candidate manifest used by a transaction.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateManifest {
    /// Candidate generation identity.
    pub generation: PlatformHandle,
    /// Component identities included in the candidate.
    pub components: Vec<PlatformHandle>,
    /// SHA-256 digest of the approved Kernel image.
    pub kernel_artifact_digest: PlatformHandle,
    /// SHA-256 digest of the approved Store bridge image. The bridge is route
    /// evidence only and is not a Host-owned process.
    pub store_bridge_artifact_digest: PlatformHandle,
    /// SHA-256 digest of the approved canonical Store engine image.
    pub canonical_store_artifact_digest: PlatformHandle,
    /// Canonical installation-approved Kernel executable path.
    pub kernel_executable_path: PlatformHandle,
    /// Canonical installation-approved eliot-store-surreal bridge path.
    pub store_bridge_executable_path: PlatformHandle,
    /// Canonical installation-approved Surreal engine path.
    pub canonical_store_executable_path: PlatformHandle,
    /// Canonical installation-approved generation configuration path.
    pub config_path: PlatformHandle,
    /// Executable/dependency closure evidence.
    pub dependency_closure_refs: Vec<PlatformHandle>,
    /// License and source assurance evidence.
    pub license_refs: Vec<PlatformHandle>,
    /// Candidate configuration digest.
    pub config_digest: PlatformHandle,
    /// Installation-approved public-key fingerprint for supervision leases.
    pub supervision_key_fingerprint: PlatformHandle,
    /// Signature/approval evidence reference.
    pub signature_ref: PlatformHandle,
    /// Exact Host-owned runtime launch contour bound to this approval.
    pub runtime_launch: RuntimeLaunchDescriptor,
}

/// Immutable, digest-bound process launch inputs owned by Host.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLaunchDescriptor {
    /// Installation profile selected for this generation.
    pub profile: InstallationProfile,
    /// Canonical repository root for `portable_dev`, when applicable.
    pub portable_root: Option<PlatformHandle>,
    /// Explicit Kernel working directory.
    pub kernel_work_root: PlatformHandle,
    /// SHA-256 digest of the approved Kernel image.
    pub kernel_artifact_digest: PlatformHandle,
    /// Explicit concrete Store bridge configuration path.
    pub store_config_path: PlatformHandle,
    /// Approved Store bridge image retained for the later Kernel route.
    pub store_bridge_executable_path: PlatformHandle,
    /// SHA-256 digest of the approved Store bridge image.
    pub store_bridge_artifact_digest: PlatformHandle,
    /// Neutral Store bootstrap descriptor consumed by Kernel.
    pub store_bootstrap_descriptor_path: PlatformHandle,
    /// SHA-256 digest of the neutral Store bootstrap descriptor.
    pub store_bootstrap_descriptor_digest: PlatformHandle,
    /// Approved canonical Surreal engine artifact path.
    pub canonical_store_executable_path: PlatformHandle,
    /// SHA-256 digest of the canonical Surreal engine image.
    pub canonical_store_artifact_digest: PlatformHandle,
    /// Exact Kernel child arguments, excluding argv[0].
    pub kernel_arguments: Vec<PlatformHandle>,
    /// Exact canonical Surreal engine arguments, excluding argv[0].
    pub canonical_store_arguments: Vec<PlatformHandle>,
    /// Canonical SCM Watchdog image and its approved digest.
    pub watchdog_executable_path: PlatformHandle,
    /// SHA-256 digest of the Watchdog image.
    pub watchdog_artifact_digest: PlatformHandle,
    /// SHA-256 of the descriptor fields excluding this digest.
    pub descriptor_digest: PlatformHandle,
}

impl RuntimeLaunchDescriptor {
    fn expected_store_arguments(&self, config_path: &PlatformHandle) -> Vec<String> {
        match self.profile {
            InstallationProfile::PortableDev => vec![
                "--portable-dev-root".to_owned(),
                self.portable_root
                    .as_ref()
                    .map_or_else(String::new, |root| root.as_str().to_owned()),
                "--config".to_owned(),
                config_path.as_str().to_owned(),
            ],
            InstallationProfile::SystemService | InstallationProfile::UserMode => {
                vec!["--config".to_owned(), config_path.as_str().to_owned()]
            }
        }
    }

    fn expected_kernel_arguments(&self, config_path: &PlatformHandle) -> Vec<String> {
        let _ = config_path;
        vec![
            "--work-root".to_owned(),
            self.kernel_work_root.as_str().to_owned(),
            "--store-bootstrap".to_owned(),
            self.store_bootstrap_descriptor_path.as_str().to_owned(),
        ]
    }

    /// Validates the launch contour against the exact approved generation
    /// configuration. Child argv is an authority input, not caller metadata.
    pub fn validate_for_config(
        &self,
        config_path: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        if self.store_config_path != *config_path {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.store_config_path".to_owned(),
                reason: "must exactly equal the approved concrete Store config".to_owned(),
            });
        }
        let expected_store = self.expected_store_arguments(config_path);
        let expected_kernel = self.expected_kernel_arguments(config_path);
        let actual_store = self
            .canonical_store_arguments
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        let actual_kernel = self
            .kernel_arguments
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        if actual_store != expected_store {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.canonical_store_arguments".to_owned(),
                reason: "must exactly select the approved generation config".to_owned(),
            });
        }
        if actual_kernel != expected_kernel {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.kernel_arguments".to_owned(),
                reason: "must exactly select the approved generation config".to_owned(),
            });
        }
        Ok(())
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, InstallationError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            profile: InstallationProfile,
            portable_root: &'a Option<PlatformHandle>,
            kernel_work_root: &'a PlatformHandle,
            kernel_artifact_digest: &'a PlatformHandle,
            store_config_path: &'a PlatformHandle,
            store_bootstrap_descriptor_path: &'a PlatformHandle,
            store_bootstrap_descriptor_digest: &'a PlatformHandle,
            canonical_store_executable_path: &'a PlatformHandle,
            canonical_store_artifact_digest: &'a PlatformHandle,
            kernel_arguments: &'a [PlatformHandle],
            store_bridge_executable_path: &'a PlatformHandle,
            store_bridge_artifact_digest: &'a PlatformHandle,
            canonical_store_arguments: &'a [PlatformHandle],
            watchdog_executable_path: &'a PlatformHandle,
            watchdog_artifact_digest: &'a PlatformHandle,
        }
        serde_json::to_vec(&Unsigned {
            profile: self.profile,
            portable_root: &self.portable_root,
            kernel_work_root: &self.kernel_work_root,
            kernel_artifact_digest: &self.kernel_artifact_digest,
            store_config_path: &self.store_config_path,
            store_bootstrap_descriptor_path: &self.store_bootstrap_descriptor_path,
            store_bootstrap_descriptor_digest: &self.store_bootstrap_descriptor_digest,
            canonical_store_executable_path: &self.canonical_store_executable_path,
            canonical_store_artifact_digest: &self.canonical_store_artifact_digest,
            kernel_arguments: &self.kernel_arguments,
            store_bridge_executable_path: &self.store_bridge_executable_path,
            store_bridge_artifact_digest: &self.store_bridge_artifact_digest,
            canonical_store_arguments: &self.canonical_store_arguments,
            watchdog_executable_path: &self.watchdog_executable_path,
            watchdog_artifact_digest: &self.watchdog_artifact_digest,
        })
        .map_err(|error| InstallationError::InvalidField {
            field: "manifest.runtime_launch".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the explicit launch contour and its self-digest.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.kernel_work_root, "runtime_launch.kernel_work_root")?;
        approved_path(&self.kernel_work_root, "runtime_launch.kernel_work_root")?;
        sha256_handle(
            &self.kernel_artifact_digest,
            "runtime_launch.kernel_artifact_digest",
        )?;
        handle(&self.store_config_path, "runtime_launch.store_config_path")?;
        approved_path(&self.store_config_path, "runtime_launch.store_config_path")?;
        handle(
            &self.store_bootstrap_descriptor_path,
            "runtime_launch.store_bootstrap_descriptor_path",
        )?;
        approved_path(
            &self.store_bootstrap_descriptor_path,
            "runtime_launch.store_bootstrap_descriptor_path",
        )?;
        sha256_handle(
            &self.store_bootstrap_descriptor_digest,
            "runtime_launch.store_bootstrap_descriptor_digest",
        )?;
        handle(
            &self.canonical_store_executable_path,
            "runtime_launch.canonical_store_executable_path",
        )?;
        approved_path(
            &self.canonical_store_executable_path,
            "runtime_launch.canonical_store_executable_path",
        )?;
        approved_filename(
            &self.canonical_store_executable_path,
            "surreal.exe",
            "runtime_launch.canonical_store_executable_path",
        )?;
        sha256_handle(
            &self.canonical_store_artifact_digest,
            "runtime_launch.canonical_store_artifact_digest",
        )?;
        approved_path(
            &self.store_bridge_executable_path,
            "runtime_launch.store_bridge_executable_path",
        )?;
        approved_filename(
            &self.store_bridge_executable_path,
            "eliot-store-surreal.exe",
            "runtime_launch.store_bridge_executable_path",
        )?;
        sha256_handle(
            &self.store_bridge_artifact_digest,
            "runtime_launch.store_bridge_artifact_digest",
        )?;
        approved_path(
            &self.watchdog_executable_path,
            "runtime_launch.watchdog_executable_path",
        )?;
        approved_filename(
            &self.watchdog_executable_path,
            "eliot-watchdog.exe",
            "runtime_launch.watchdog_executable_path",
        )?;
        sha256_handle(
            &self.watchdog_artifact_digest,
            "runtime_launch.watchdog_artifact_digest",
        )?;
        match (self.profile, &self.portable_root) {
            (InstallationProfile::PortableDev, Some(root)) => {
                approved_path(root, "runtime_launch.portable_root")?;
            }
            (InstallationProfile::PortableDev, None) => {
                return Err(InstallationError::ProfileViolation(
                    "portable_dev requires an explicit portable root".to_owned(),
                ));
            }
            (_, Some(_)) => {
                return Err(InstallationError::ProfileViolation(
                    "portable root is only valid for portable_dev".to_owned(),
                ));
            }
            (_, None) => {}
        }
        for (arguments, field) in [
            (&self.kernel_arguments, "runtime_launch.kernel_arguments"),
            (
                &self.canonical_store_arguments,
                "runtime_launch.canonical_store_arguments",
            ),
        ] {
            for argument in arguments {
                handle(argument, field)?;
            }
        }
        sha256_handle(&self.descriptor_digest, "runtime_launch.descriptor_digest")?;
        let actual = Sha256::digest(&self.unsigned_bytes()?);
        if format!("{actual:x}") != self.descriptor_digest.as_str() {
            return Err(InstallationError::InvalidField {
                field: "runtime_launch.descriptor_digest".to_owned(),
                reason: "descriptor digest mismatch".to_owned(),
            });
        }
        Ok(())
    }
}

impl CandidateManifest {
    /// Validates candidate identity and complete assurance references.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.generation, "manifest.generation")?;
        handles(&self.components, "manifest.components", true)?;
        sha256_handle(
            &self.kernel_artifact_digest,
            "manifest.kernel_artifact_digest",
        )?;
        sha256_handle(
            &self.store_bridge_artifact_digest,
            "manifest.store_bridge_artifact_digest",
        )?;
        sha256_handle(
            &self.canonical_store_artifact_digest,
            "manifest.canonical_store_artifact_digest",
        )?;
        approved_path(
            &self.kernel_executable_path,
            "manifest.kernel_executable_path",
        )?;
        approved_filename(
            &self.kernel_executable_path,
            "eliot-kernel.exe",
            "manifest.kernel_executable_path",
        )?;
        approved_path(
            &self.store_bridge_executable_path,
            "manifest.store_bridge_executable_path",
        )?;
        approved_filename(
            &self.store_bridge_executable_path,
            "eliot-store-surreal.exe",
            "manifest.store_bridge_executable_path",
        )?;
        approved_path(
            &self.canonical_store_executable_path,
            "manifest.canonical_store_executable_path",
        )?;
        approved_filename(
            &self.canonical_store_executable_path,
            "surreal.exe",
            "manifest.canonical_store_executable_path",
        )?;
        if self.kernel_executable_path == self.store_bridge_executable_path
            || self.kernel_executable_path == self.canonical_store_executable_path
            || self.store_bridge_executable_path == self.canonical_store_executable_path
        {
            return Err(InstallationError::Duplicate {
                kind: "manifest.named_artifact_paths".to_owned(),
                identity: "aliased executable path".to_owned(),
            });
        }
        approved_path(&self.config_path, "manifest.config_path")?;
        if self.runtime_launch.store_config_path != self.config_path {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.store_config_path".to_owned(),
                reason: "must exactly equal the approved manifest config_path".to_owned(),
            });
        }
        if self.runtime_launch.store_bootstrap_descriptor_path == self.config_path {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.store_bootstrap_descriptor_path".to_owned(),
                reason: "neutral descriptor must be distinct from concrete Store config".to_owned(),
            });
        }
        if self.runtime_launch.canonical_store_executable_path
            != self.canonical_store_executable_path
        {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.canonical_store_executable_path".to_owned(),
                reason: "must exactly equal the approved canonical engine path".to_owned(),
            });
        }
        if self.runtime_launch.store_bridge_executable_path != self.store_bridge_executable_path
            || self.runtime_launch.kernel_artifact_digest != self.kernel_artifact_digest
            || self.runtime_launch.store_bridge_artifact_digest != self.store_bridge_artifact_digest
            || self.runtime_launch.canonical_store_artifact_digest
                != self.canonical_store_artifact_digest
        {
            return Err(InstallationError::InvalidField {
                field: "manifest.runtime_launch.artifact_bindings".to_owned(),
                reason: "named artifact bindings do not exactly match the manifest".to_owned(),
            });
        }
        handles(
            &self.dependency_closure_refs,
            "manifest.dependency_closure_refs",
            true,
        )?;
        handles(&self.license_refs, "manifest.license_refs", true)?;
        sha256_handle(&self.config_digest, "manifest.config_digest")?;
        sha256_handle(
            &self.supervision_key_fingerprint,
            "manifest.supervision_key_fingerprint",
        )?;
        handle(&self.signature_ref, "manifest.signature_ref")
            .and_then(|()| self.runtime_launch.validate_for_config(&self.config_path))
    }

    /// Returns the named Kernel, canonical Store, and bridge artifact digests.
    pub fn runtime_artifact_digests(
        &self,
    ) -> Result<(&PlatformHandle, &PlatformHandle, &PlatformHandle), InstallationError> {
        self.validate()?;
        Ok((
            &self.kernel_artifact_digest,
            &self.canonical_store_artifact_digest,
            &self.store_bridge_artifact_digest,
        ))
    }

    /// Returns the canonical Kernel, canonical Store engine and configuration paths.
    pub fn runtime_paths(&self) -> (&PlatformHandle, &PlatformHandle, &PlatformHandle) {
        (
            &self.kernel_executable_path,
            &self.canonical_store_executable_path,
            &self.config_path,
        )
    }
}

/// One artifact generation admitted by installation policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedGeneration {
    /// The complete immutable candidate manifest.
    pub manifest: CandidateManifest,
    /// Non-secret approval evidence reference.
    pub approval_ref: PlatformHandle,
    /// Whether this generation is currently active.
    pub active: bool,
    /// Whether this generation is the last-known-good activation.
    pub last_known_good: bool,
}

impl ApprovedGeneration {
    /// Validates the generation and its approval reference.
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.manifest.validate()?;
        handle(&self.approval_ref, "approved_generation.approval_ref")
    }
}

/// Installation-owned approved-generation and last-known-good registry.
///
/// The registry admits only complete [`CandidateManifest`] values. Activation
/// is a bounded state transition: an unknown generation cannot become active,
/// and rollback selects the previously recorded last-known-good generation.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedGenerationRegistry {
    /// Approved generations keyed by their exact generation identity.
    pub generations: Vec<ApprovedGeneration>,
    /// Currently active generation identity, when one is active.
    pub active_generation: Option<PlatformHandle>,
    /// Last-known-good generation identity, when one is available.
    pub last_known_good_generation: Option<PlatformHandle>,
}

const REGISTRY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_approved_generations_v1");
const REGISTRY_RELATIVE_PATH: &str = "Eliot/host/installation-registry.redb";

/// Durable redb owner for approved generations and LKG activation state.
pub struct RedbInstallationRegistry {
    database: Database,
    _path_lease: ProtectedPathLease,
}

impl RedbInstallationRegistry {
    /// Opens or creates the registry database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, InstallationError> {
        let path = path.as_ref();
        require_protected_program_data_path(path, REGISTRY_RELATIVE_PATH)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let path_lease = ProtectedPathLease::open_or_create(REGISTRY_RELATIVE_PATH)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if path_lease.path() != path {
            return Err(InstallationError::Platform(
                "registry path is not the exact protected ProgramData path".to_owned(),
            ));
        }
        let database = Database::create(path_lease.path())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        path_lease
            .verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Self {
            database,
            _path_lease: path_lease,
        })
    }

    /// Loads the registry, returning an empty value on first use.
    pub fn load(&self) -> Result<ApprovedGenerationRegistry, InstallationError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let table = match read.open_table(REGISTRY_TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(ApprovedGenerationRegistry::new());
            }
            Err(error) => return Err(InstallationError::Platform(error.to_string())),
        };
        let Some(value) = table
            .get("registry")
            .map_err(|error| InstallationError::Platform(error.to_string()))?
        else {
            return Ok(ApprovedGenerationRegistry::new());
        };
        let registry: ApprovedGenerationRegistry = serde_json::from_slice(value.value())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        // A durable registry is an authority projection, not an opaque cache.
        // Never allow malformed or contradictory bytes to become an empty or
        // partially trusted activation decision.
        registry.validate()?;
        Ok(registry)
    }

    /// Durably stores one complete validated registry projection.
    pub fn save(&self, registry: &ApprovedGenerationRegistry) -> Result<(), InstallationError> {
        registry.validate()?;
        let bytes = serde_json::to_vec(registry)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        {
            let mut table = write
                .open_table(REGISTRY_TABLE)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            table
                .insert("registry", bytes.as_slice())
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
        }
        write
            .commit()
            .map_err(|error| InstallationError::Platform(error.to_string()))
    }
}

impl ApprovedGenerationRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generations: Vec::new(),
            active_generation: None,
            last_known_good_generation: None,
        }
    }

    /// Approves one exact candidate generation.
    pub fn approve(
        &mut self,
        manifest: CandidateManifest,
        approval_ref: PlatformHandle,
    ) -> Result<(), InstallationError> {
        manifest.validate()?;
        handle(&approval_ref, "approved_generation.approval_ref")?;
        if self
            .generations
            .iter()
            .any(|generation| generation.manifest.generation == manifest.generation)
        {
            return Err(InstallationError::Duplicate {
                kind: "approved generation".to_owned(),
                identity: manifest.generation.as_str().to_owned(),
            });
        }
        self.generations.push(ApprovedGeneration {
            manifest,
            approval_ref,
            active: false,
            last_known_good: false,
        });
        self.validate()?;
        Ok(())
    }

    /// Activates an approved generation and records the prior active
    /// generation as last-known-good before crossing the activation boundary.
    pub fn activate(&mut self, generation: &PlatformHandle) -> Result<(), InstallationError> {
        self.validate()?;
        let selected = self
            .generations
            .iter()
            .position(|item| &item.manifest.generation == generation)
            .ok_or_else(|| {
                InstallationError::IncompleteObservation("generation is not approved".to_owned())
            })?;
        if self.active_generation.as_ref() == Some(generation) {
            // Reactivation is idempotent, but still requires the full
            // projection to be internally consistent.
            return Ok(());
        }
        let previous = self.active_generation.take();
        self.last_known_good_generation.clone_from(&previous);
        for item in &mut self.generations {
            item.active = false;
            // A cutover has exactly one LKG: the generation that was active
            // immediately before this transition.  Clear any stale marker
            // before setting that projection below.
            item.last_known_good = false;
        }
        if let Some(previous) = previous
            && let Some(item) = self
                .generations
                .iter_mut()
                .find(|item| item.manifest.generation == previous)
        {
            item.last_known_good = true;
        }
        self.generations[selected].active = true;
        self.generations[selected].last_known_good = false;
        self.active_generation = Some(generation.clone());
        self.validate()?;
        Ok(())
    }

    /// Activates the last-known-good generation for bounded rollback.
    pub fn rollback(&mut self) -> Result<PlatformHandle, InstallationError> {
        let generation = self.last_known_good_generation.clone().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "last-known-good generation is unavailable".to_owned(),
            )
        })?;
        let prior_active = self.active_generation.clone();
        self.activate(&generation)?;
        // The generation we just left is the one that failed the cutover; it
        // must not remain advertised as LKG after rollback.
        if prior_active.as_ref() != Some(&generation) {
            if let Some(prior) = prior_active
                && let Some(item) = self
                    .generations
                    .iter_mut()
                    .find(|item| item.manifest.generation == prior)
            {
                item.last_known_good = false;
            }
            self.last_known_good_generation = None;
        }
        self.validate()?;
        Ok(generation)
    }

    /// Returns the currently active approved generation.
    #[must_use]
    pub fn active(&self) -> Option<&ApprovedGeneration> {
        self.active_generation.as_ref().and_then(|generation| {
            self.generations
                .iter()
                .find(|item| &item.manifest.generation == generation && item.active)
        })
    }

    /// Validates the complete registry projection and all generation entries.
    pub fn validate(&self) -> Result<(), InstallationError> {
        let mut identities = BTreeSet::new();
        let mut active_count = 0_usize;
        let mut lkg_count = 0_usize;
        for generation in &self.generations {
            generation.validate()?;
            if !identities.insert(generation.manifest.generation.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "approved generation".to_owned(),
                    identity: generation.manifest.generation.as_str().to_owned(),
                });
            }
            if generation.active {
                active_count += 1;
            }
            if generation.last_known_good {
                lkg_count += 1;
            }
        }
        if active_count > 1 {
            return Err(InstallationError::IncompleteObservation(
                "registry contains multiple active generations".to_owned(),
            ));
        }
        if lkg_count > 1 {
            return Err(InstallationError::IncompleteObservation(
                "registry contains multiple last-known-good generations".to_owned(),
            ));
        }
        if let Some(active) = &self.active_generation {
            if active_count != 1
                || !self
                    .generations
                    .iter()
                    .any(|item| item.active && item.manifest.generation == *active)
            {
                return Err(InstallationError::IncompleteObservation(
                    "active generation is absent from registry".to_owned(),
                ));
            }
        } else if active_count != 0 {
            return Err(InstallationError::IncompleteObservation(
                "active generation flag has no registry identity".to_owned(),
            ));
        }
        if let Some(lkg) = &self.last_known_good_generation {
            if lkg_count != 1
                || !self
                    .generations
                    .iter()
                    .any(|item| item.last_known_good && item.manifest.generation == *lkg)
            {
                return Err(InstallationError::IncompleteObservation(
                    "last-known-good generation is absent from registry".to_owned(),
                ));
            }
            if self.active_generation.as_ref() == Some(lkg) {
                return Err(InstallationError::IncompleteObservation(
                    "active generation cannot also be last-known-good".to_owned(),
                ));
            }
        } else if lkg_count != 0 {
            return Err(InstallationError::IncompleteObservation(
                "last-known-good flag has no registry identity".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A planned immutable change to an OS registration, file or plugin surface.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedChange {
    /// Stable change identity.
    pub change_id: PlatformHandle,
    /// External object/reference affected by the change.
    pub target: PlatformHandle,
    /// Exact precondition evidence.
    pub precondition_refs: Vec<PlatformHandle>,
    /// Expected postcondition evidence.
    pub postcondition_refs: Vec<PlatformHandle>,
}

impl PlannedChange {
    /// Validates one planned external change.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.change_id, "change_id")?;
        handle(&self.target, "change.target")?;
        handles(&self.precondition_refs, "change.precondition_refs", true)?;
        handles(&self.postcondition_refs, "change.postcondition_refs", true)
    }
}

/// Durable installer stage. A partial external effect cannot skip recovery.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationStage {
    /// Immutable plan exists but no external effect has started.
    Planned,
    /// Candidate bytes are being copied into an isolated staging root.
    Staging,
    /// Hashes/signatures/dependency closure have been observed.
    StaticVerified,
    /// Candidate registrations are being prepared without authority.
    Registering,
    /// The activation pointer or service configuration is being switched.
    Activating,
    /// Runtime health and conformance have been observed.
    ActiveVerified,
    /// Superseded staging and registrations are being removed.
    Cleaning,
    /// Transaction has completed with an observed disposition.
    Completed,
    /// External outcome is unknown and requires reconciliation or rollback.
    RollbackRequired,
    /// Candidate was rolled back with an observed disposition.
    RolledBack,
    /// Recovery could not safely determine a disposition.
    Quarantined,
}

impl InstallationStage {
    fn can_advance(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Planned, Self::Staging)
                | (Self::Staging, Self::StaticVerified | Self::RollbackRequired)
                | (
                    Self::StaticVerified,
                    Self::Registering | Self::RollbackRequired
                )
                | (Self::Registering, Self::Activating | Self::RollbackRequired)
                | (
                    Self::Activating,
                    Self::ActiveVerified | Self::RollbackRequired
                )
                | (Self::ActiveVerified, Self::Cleaning | Self::Completed)
                | (Self::Cleaning, Self::Completed | Self::RollbackRequired)
                | (Self::RollbackRequired, Self::RolledBack | Self::Quarantined)
        )
    }
}

/// Durable installation/update transaction and its recovery projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationTransaction {
    /// Stable transaction identity.
    pub transaction_id: PlatformHandle,
    /// Installation lineage at transaction creation.
    pub installation_epoch: InstallationEpoch,
    /// Selected path/supervision profile.
    pub profile: InstallationProfile,
    /// Governing request identity.
    pub request: ManagedEnvironmentChangeRequest,
    /// Previously active generation, if one exists.
    pub current_active_manifest: Option<CandidateManifest>,
    /// Immutable candidate generation.
    pub candidate_manifest: CandidateManifest,
    /// Isolated staging root.
    pub staging_root: PlatformHandle,
    /// Planned OS/file/plugin/service changes.
    pub planned_changes: Vec<PlannedChange>,
    /// Precondition observations captured before staging.
    pub precondition_evidence: Vec<PlatformHandle>,
    /// Current durable stage.
    pub stage: InstallationStage,
    /// Evidence references for completed stages.
    pub completed_stage_refs: Vec<PlatformHandle>,
    /// External objects changed but not yet acknowledged.
    pub pending_external_changes: Vec<PlatformHandle>,
    /// Rollback or forward-repair plan.
    pub rollback_plan: PlatformHandle,
    /// Last-known-good manifest/generation reference.
    pub last_known_good: Option<PlatformHandle>,
    /// No-return boundary evidence, when activation crossed it.
    pub no_return_boundary: Option<PlatformHandle>,
    /// Observed postconditions.
    pub observed_postconditions: Vec<PlatformHandle>,
    /// Operator recovery command/reference.
    pub recovery_command: PlatformHandle,
    /// Monotonic state revision.
    pub revision: u64,
}

impl InstallationTransaction {
    /// Creates a validated immutable plan at `PLANNED`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_id: PlatformHandle,
        installation_epoch: InstallationEpoch,
        profile: InstallationProfile,
        request: ManagedEnvironmentChangeRequest,
        current_active_manifest: Option<CandidateManifest>,
        candidate_manifest: CandidateManifest,
        staging_root: PlatformHandle,
        planned_changes: Vec<PlannedChange>,
        precondition_evidence: Vec<PlatformHandle>,
        recovery_command: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        handle(&transaction_id, "transaction_id")?;
        installation_epoch.validate()?;
        request.validate()?;
        candidate_manifest.validate()?;
        if let Some(manifest) = &current_active_manifest {
            manifest.validate()?;
        }
        handle(&staging_root, "staging_root")?;
        handle(&recovery_command, "recovery_command")?;
        handles(&precondition_evidence, "precondition_evidence", true)?;
        let mut change_ids = BTreeSet::new();
        for change in &planned_changes {
            change.validate()?;
            if !change_ids.insert(change.change_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "planned change".to_owned(),
                    identity: change.change_id.as_str().to_owned(),
                });
            }
        }
        if planned_changes.is_empty() {
            return Err(InstallationError::InvalidField {
                field: "planned_changes".to_owned(),
                reason: "must contain an explicit effect plan".to_owned(),
            });
        }
        if profile.is_disposable() && staging_root.as_str().contains("..") {
            return Err(InstallationError::ProfileViolation(
                "portable staging root must remain repository-local".to_owned(),
            ));
        }
        let rollback_plan = request.rollback_plan.clone();
        Ok(Self {
            transaction_id,
            installation_epoch,
            profile,
            request,
            current_active_manifest,
            candidate_manifest,
            staging_root,
            planned_changes,
            precondition_evidence,
            stage: InstallationStage::Planned,
            completed_stage_refs: Vec::new(),
            pending_external_changes: Vec::new(),
            rollback_plan,
            last_known_good: None,
            no_return_boundary: None,
            observed_postconditions: Vec::new(),
            recovery_command,
            revision: 1,
        })
    }

    /// Validates the complete transaction projection.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.transaction_id, "transaction_id")?;
        self.installation_epoch.validate()?;
        self.request.validate()?;
        self.candidate_manifest.validate()?;
        if let Some(manifest) = &self.current_active_manifest {
            manifest.validate()?;
        }
        handle(&self.staging_root, "staging_root")?;
        handle(&self.rollback_plan, "rollback_plan")?;
        handle(&self.recovery_command, "recovery_command")?;
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        handles(&self.precondition_evidence, "precondition_evidence", true)?;
        handles(&self.completed_stage_refs, "completed_stage_refs", false)?;
        handles(
            &self.pending_external_changes,
            "pending_external_changes",
            false,
        )?;
        handles(
            &self.observed_postconditions,
            "observed_postconditions",
            false,
        )?;
        if matches!(
            self.stage,
            InstallationStage::ActiveVerified | InstallationStage::Completed
        ) && self.observed_postconditions.is_empty()
        {
            return Err(InstallationError::IncompleteObservation(
                "active/completed transaction requires postcondition evidence".to_owned(),
            ));
        }
        if matches!(self.stage, InstallationStage::RollbackRequired)
            && self.pending_external_changes.is_empty()
        {
            return Err(InstallationError::IncompleteObservation(
                "rollback-required transaction must name pending external changes".to_owned(),
            ));
        }
        if matches!(
            self.stage,
            InstallationStage::RolledBack | InstallationStage::Quarantined
        ) && self.pending_external_changes.is_empty()
            && self.completed_stage_refs.is_empty()
        {
            return Err(InstallationError::IncompleteObservation(
                "terminal recovery state requires disposition evidence".to_owned(),
            ));
        }
        Ok(())
    }

    /// Advances one stage using observed evidence and increments the revision.
    pub fn advance(
        &mut self,
        next: InstallationStage,
        evidence: Vec<PlatformHandle>,
    ) -> Result<(), InstallationError> {
        if !self.stage.can_advance(next) {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: next,
            });
        }
        handles(&evidence, "stage_evidence", true)?;
        self.completed_stage_refs.extend(evidence);
        if next == InstallationStage::ActiveVerified {
            self.observed_postconditions
                .extend(self.completed_stage_refs.clone());
        }
        self.stage = next;
        self.revision =
            self.revision
                .checked_add(1)
                .ok_or_else(|| InstallationError::InvalidField {
                    field: "revision".to_owned(),
                    reason: "overflow".to_owned(),
                })?;
        self.validate()
    }

    /// Records an external effect whose outcome cannot yet be classified.
    pub fn mark_unknown(&mut self, pending: Vec<PlatformHandle>) -> Result<(), InstallationError> {
        handles(&pending, "pending_external_changes", true)?;
        if !self.stage.can_advance(InstallationStage::RollbackRequired) {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::RollbackRequired,
            });
        }
        self.pending_external_changes = pending;
        self.stage = InstallationStage::RollbackRequired;
        self.revision =
            self.revision
                .checked_add(1)
                .ok_or_else(|| InstallationError::InvalidField {
                    field: "revision".to_owned(),
                    reason: "overflow".to_owned(),
                })?;
        self.validate()
    }

    /// Records a no-return activation boundary after explicit observation.
    pub fn record_no_return_boundary(
        &mut self,
        reference: PlatformHandle,
    ) -> Result<(), InstallationError> {
        handle(&reference, "no_return_boundary")?;
        if !matches!(
            self.stage,
            InstallationStage::Activating | InstallationStage::ActiveVerified
        ) {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::ActiveVerified,
            });
        }
        self.no_return_boundary = Some(reference);
        self.validate()
    }
}

fn platform_error(error: &PortError) -> InstallationError {
    InstallationError::Platform(error.to_string())
}

/// Bounded external installation operation selected by the transaction owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationEffectOperation {
    /// Copy candidate bytes into an isolated staging root.
    Stage,
    /// Register candidate service/tasks/plugins without activation authority.
    Register,
    /// Switch the selected activation pointer or service configuration.
    Activate,
    /// Remove superseded staging/registrations after the rollback window.
    Clean,
    /// Apply the explicit rollback or forward-repair plan.
    Rollback,
}

/// Request sent to the effect executor; it carries references, never payload bytes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationEffectRequest {
    /// Transaction identity.
    pub transaction_id: PlatformHandle,
    /// Installation identity.
    pub installation: PlatformHandle,
    /// Selected profile.
    pub profile: InstallationProfile,
    /// Effect operation.
    pub operation: InstallationEffectOperation,
    /// Candidate generation.
    pub candidate_generation: PlatformHandle,
    /// Exact planned changes selected for this operation.
    pub change_refs: Vec<PlatformHandle>,
    /// Rollback/recovery plan reference.
    pub rollback_plan: PlatformHandle,
}

impl InstallationEffectRequest {
    /// Validates an effect request before it crosses the adapter boundary.
    pub fn validate(&self) -> Result<(), InstallationError> {
        for (value, field) in [
            (&self.transaction_id, "effect.transaction_id"),
            (&self.installation, "effect.installation"),
            (&self.candidate_generation, "effect.candidate_generation"),
            (&self.rollback_plan, "effect.rollback_plan"),
        ] {
            handle(value, field)?;
        }
        handles(
            &self.change_refs,
            "effect.change_refs",
            self.operation != InstallationEffectOperation::Rollback,
        )
    }
}

/// Observed postcondition returned by an effect executor.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationEffectObservation {
    /// Echoed transaction identity.
    pub transaction_id: PlatformHandle,
    /// Operation actually observed.
    pub operation: InstallationEffectOperation,
    /// Provider/external object identity observed after the effect.
    pub external_identity: PlatformHandle,
    /// Evidence proving the effect and its postcondition.
    pub evidence_refs: Vec<PlatformHandle>,
    /// Whether the external object crossed its no-return boundary.
    pub crossed_no_return: bool,
}

impl InstallationEffectObservation {
    /// Validates an observed effect without asserting semantic capability health.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.transaction_id, "observation.transaction_id")?;
        handle(&self.external_identity, "observation.external_identity")?;
        handles(&self.evidence_refs, "observation.evidence_refs", true)?;
        if self.crossed_no_return && self.operation != InstallationEffectOperation::Activate {
            return Err(InstallationError::InvalidField {
                field: "observation.crossed_no_return".to_owned(),
                reason: "only activation may cross the no-return boundary".to_owned(),
            });
        }
        Ok(())
    }
}

/// Object-safe adapter seam for bounded installation effects.
pub trait InstallationEffectPort: Send {
    /// Executes one operation and reports known, partial or unknown outcome.
    fn execute(
        &mut self,
        request: &InstallationEffectRequest,
    ) -> PortOutcome<InstallationEffectObservation>;
}

/// Result of one coordinator step.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationStepOutcome {
    /// The effect was observed and the transaction advanced.
    Applied {
        /// Durable stage reached after the observed effect.
        stage: InstallationStage,
        /// Evidence references proving the effect postcondition.
        evidence_refs: Vec<PlatformHandle>,
    },
    /// The effect changed an object but complete postcondition evidence is absent.
    RollbackRequired {
        /// Evidence references that must be reconciled before rollback.
        pending_refs: Vec<PlatformHandle>,
    },
    /// Rollback itself is indeterminate and the transaction is quarantined.
    Quarantined {
        /// External identities still requiring operator reconciliation.
        pending_refs: Vec<PlatformHandle>,
    },
    /// The effect could not be admitted before changing an external object.
    Rejected,
}

/// Coordinates one installation transaction without owning platform mechanics.
pub struct InstallationCoordinator<P> {
    port: P,
}

impl<P> InstallationCoordinator<P>
where
    P: InstallationEffectPort,
{
    /// Creates a coordinator around one platform effect port.
    #[must_use]
    pub const fn new(port: P) -> Self {
        Self { port }
    }

    /// Borrows the underlying effect port for composition or inspection.
    #[must_use]
    pub const fn port(&self) -> &P {
        &self.port
    }

    /// Applies one effect, preserving unknown outcomes as rollback-required.
    pub fn apply(
        &mut self,
        transaction: &mut InstallationTransaction,
        operation: InstallationEffectOperation,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        transaction.validate()?;
        let expected = expected_stage(transaction.stage, operation)?;
        let request = InstallationEffectRequest {
            transaction_id: transaction.transaction_id.clone(),
            installation: transaction.installation_epoch.installation.clone(),
            profile: transaction.profile,
            operation,
            candidate_generation: transaction.candidate_manifest.generation.clone(),
            change_refs: transaction
                .planned_changes
                .iter()
                .map(|change| change.change_id.clone())
                .collect(),
            rollback_plan: transaction.rollback_plan.clone(),
        };
        request.validate()?;
        let outcome = self.port.execute(&request);
        match outcome {
            PortOutcome::Known(observation) => {
                observation.validate()?;
                if observation.transaction_id != transaction.transaction_id
                    || observation.operation != operation
                {
                    return Err(InstallationError::IdentityConflict);
                }
                if observation.crossed_no_return {
                    let mut activated = transaction.clone();
                    activated.advance(expected, observation.evidence_refs.clone())?;
                    activated.record_no_return_boundary(observation.external_identity.clone())?;
                    *transaction = activated;
                } else {
                    transaction.advance(expected, observation.evidence_refs.clone())?;
                }
                if operation == InstallationEffectOperation::Rollback {
                    transaction.pending_external_changes.clear();
                }
                Ok(InstallationStepOutcome::Applied {
                    stage: transaction.stage,
                    evidence_refs: observation.evidence_refs,
                })
            }
            PortOutcome::Partial { value, missing } => {
                value.validate()?;
                let mut pending = missing;
                pending.push(value.external_identity);
                if operation == InstallationEffectOperation::Rollback {
                    transaction.advance(InstallationStage::Quarantined, pending.clone())?;
                    return Ok(InstallationStepOutcome::Quarantined {
                        pending_refs: pending,
                    });
                }
                transaction.mark_unknown(pending.clone())?;
                Ok(InstallationStepOutcome::RollbackRequired {
                    pending_refs: pending,
                })
            }
            PortOutcome::Unknown(reason) => {
                let pending = vec![
                    PlatformHandle::new(format!("unknown:{reason:?}"))
                        .map_err(|error| platform_error(&error))?,
                ];
                if operation == InstallationEffectOperation::Rollback {
                    transaction.advance(InstallationStage::Quarantined, pending.clone())?;
                    return Ok(InstallationStepOutcome::Quarantined {
                        pending_refs: pending,
                    });
                }
                transaction.mark_unknown(pending.clone())?;
                Ok(InstallationStepOutcome::RollbackRequired {
                    pending_refs: pending,
                })
            }
            PortOutcome::Error(error) => Err(platform_error(&error)),
        }
    }
}

fn expected_stage(
    current: InstallationStage,
    operation: InstallationEffectOperation,
) -> Result<InstallationStage, InstallationError> {
    let (expected, allowed) = match operation {
        InstallationEffectOperation::Stage => (
            InstallationStage::Staging,
            matches!(current, InstallationStage::Planned),
        ),
        InstallationEffectOperation::Register => (
            InstallationStage::Registering,
            current == InstallationStage::StaticVerified,
        ),
        InstallationEffectOperation::Activate => (
            InstallationStage::Activating,
            current == InstallationStage::Registering,
        ),
        InstallationEffectOperation::Clean => (
            InstallationStage::Cleaning,
            current == InstallationStage::ActiveVerified,
        ),
        InstallationEffectOperation::Rollback => (
            InstallationStage::RolledBack,
            current == InstallationStage::RollbackRequired,
        ),
    };
    if !allowed {
        return Err(InstallationError::IllegalTransition {
            from: current,
            to: expected,
        });
    }
    Ok(expected)
}

/// A read-only adapter-backed inspection helper.
pub struct InstallationInspector<P> {
    port: P,
}

impl<P> InstallationInspector<P>
where
    P: InstallationPort,
{
    /// Creates an inspector around the provider-neutral installation port.
    #[must_use]
    pub const fn new(port: P) -> Self {
        Self { port }
    }

    /// Inspects exact components without treating presence as admission.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the public inspection façade preserves its owned request contract"
    )]
    pub fn inspect(
        &mut self,
        request: InstallationRequest,
    ) -> Result<InstallationObservation, InstallationError> {
        request.validate().map_err(|error| platform_error(&error))?;
        let outcome = self.port.execute(&request);
        match outcome {
            PortOutcome::Known(observation) => Ok(observation),
            PortOutcome::Partial { .. } => Err(InstallationError::IncompleteObservation(
                "installation inspection was partial".to_owned(),
            )),
            PortOutcome::Unknown(_) => Err(InstallationError::UnknownOutcome {
                stage: InstallationStage::Planned,
            }),
            PortOutcome::Error(error) => Err(platform_error(&error)),
        }
    }

    /// Borrows the underlying platform port.
    #[must_use]
    pub const fn port(&self) -> &P {
        &self.port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct KnownEffectPort {
        observation: InstallationEffectObservation,
    }

    impl InstallationEffectPort for KnownEffectPort {
        fn execute(
            &mut self,
            _request: &InstallationEffectRequest,
        ) -> PortOutcome<InstallationEffectObservation> {
            PortOutcome::Known(self.observation.clone())
        }
    }

    fn must<T, E>(result: Result<T, E>) -> T
    where
        E: std::fmt::Display,
    {
        match result {
            Ok(value) => value,
            Err(error) => panic!("invalid installation test fixture: {error}"),
        }
    }

    fn test_handle(value: impl Into<String>) -> PlatformHandle {
        must(PlatformHandle::new(value.into()))
    }

    fn test_path(root: &Path, name: &str) -> PlatformHandle {
        test_handle(root.join(name).to_string_lossy().into_owned())
    }

    #[allow(clippy::too_many_lines)]
    fn registering_transaction() -> InstallationTransaction {
        let root = std::env::temp_dir().join("eliot-installation-activate-regression");
        let candidate_generation = test_handle("generation:candidate");
        let rollback_plan = test_handle("rollback:plan");
        let candidate_manifest = CandidateManifest {
            generation: candidate_generation.clone(),
            components: vec![
                test_handle("component:kernel"),
                test_handle("component:store"),
            ],
            kernel_artifact_digest: test_handle("0".repeat(64)),
            store_bridge_artifact_digest: test_handle("1".repeat(64)),
            canonical_store_artifact_digest: test_handle("5".repeat(64)),
            kernel_executable_path: test_path(&root, "eliot-kernel.exe"),
            store_bridge_executable_path: test_path(&root, "eliot-store-surreal.exe"),
            canonical_store_executable_path: test_path(&root, "surreal.exe"),
            config_path: test_path(&root, "generation.json"),
            dependency_closure_refs: vec![test_handle("evidence:dependency-closure")],
            license_refs: vec![test_handle("evidence:licenses")],
            config_digest: test_handle("2".repeat(64)),
            supervision_key_fingerprint: test_handle("3".repeat(64)),
            signature_ref: test_handle("evidence:signature"),
            runtime_launch: {
                let mut descriptor = RuntimeLaunchDescriptor {
                    profile: InstallationProfile::PortableDev,
                    portable_root: Some(test_path(&root, "portable")),
                    kernel_work_root: test_path(&root, "portable"),
                    kernel_artifact_digest: test_handle("0".repeat(64)),
                    store_config_path: test_path(&root, "generation.json"),
                    store_bridge_executable_path: test_path(&root, "eliot-store-surreal.exe"),
                    store_bridge_artifact_digest: test_handle("1".repeat(64)),
                    store_bootstrap_descriptor_path: test_path(&root, "store-bootstrap.json"),
                    store_bootstrap_descriptor_digest: test_handle("6".repeat(64)),
                    canonical_store_executable_path: test_path(&root, "surreal.exe"),
                    canonical_store_artifact_digest: test_handle("5".repeat(64)),
                    kernel_arguments: vec![
                        test_handle("--work-root"),
                        test_path(&root, "portable"),
                        test_handle("--store-bootstrap"),
                        test_path(&root, "store-bootstrap.json"),
                    ],
                    canonical_store_arguments: vec![
                        test_handle("--portable-dev-root"),
                        test_path(&root, "portable"),
                        test_handle("--config"),
                        test_path(&root, "generation.json"),
                    ],
                    watchdog_executable_path: test_path(&root, "eliot-watchdog.exe"),
                    watchdog_artifact_digest: test_handle("4".repeat(64)),
                    descriptor_digest: test_handle("0".repeat(64)),
                };
                let digest = Sha256::digest(must(descriptor.unsigned_bytes()));
                descriptor.descriptor_digest = test_handle(format!("{digest:x}"));
                descriptor
            },
        };
        let request = ManagedEnvironmentChangeRequest {
            request_id: test_handle("request:install"),
            requester_and_reason: test_handle("requester:test"),
            action: ManagedEnvironmentAction::Install,
            target_family: test_handle("family:eliot"),
            exact_candidate: candidate_generation,
            expected_delta: test_handle("delta:installed"),
            source_assurance_refs: vec![test_handle("evidence:source-assurance")],
            affected_refs: Vec::new(),
            impact_class: test_handle("impact:test"),
            required_owner: test_handle("owner:installation"),
            rollback_plan: rollback_plan.clone(),
            verifier: test_handle("verifier:installation"),
            budget: test_handle("budget:test"),
            stop_condition: test_handle("stop:on-failure"),
        };
        let mut transaction = must(InstallationTransaction::new(
            test_handle("transaction:activate"),
            InstallationEpoch {
                installation: test_handle("installation:test"),
                lineage_id: test_handle("lineage:test"),
                sequence: 1,
            },
            InstallationProfile::PortableDev,
            request,
            None,
            candidate_manifest,
            test_path(&root, "staging"),
            vec![PlannedChange {
                change_id: test_handle("change:activation-pointer"),
                target: test_handle("target:activation-pointer"),
                precondition_refs: vec![test_handle("evidence:precondition")],
                postcondition_refs: vec![test_handle("evidence:postcondition")],
            }],
            vec![test_handle("evidence:plan-precondition")],
            test_handle("recovery:command"),
        ));
        must(transaction.advance(
            InstallationStage::Staging,
            vec![test_handle("evidence:staged")],
        ));
        must(transaction.advance(
            InstallationStage::StaticVerified,
            vec![test_handle("evidence:static-verified")],
        ));
        must(transaction.advance(
            InstallationStage::Registering,
            vec![test_handle("evidence:registered")],
        ));
        transaction
    }

    #[test]
    fn activate_with_crossed_no_return_advances_before_recording_boundary() {
        let mut transaction = registering_transaction();
        let evidence = test_handle("evidence:activated");
        let boundary = test_handle("activation:pointer:generation-candidate");
        let starting_revision = transaction.revision;
        let observation = InstallationEffectObservation {
            transaction_id: transaction.transaction_id.clone(),
            operation: InstallationEffectOperation::Activate,
            external_identity: boundary.clone(),
            evidence_refs: vec![evidence.clone()],
            crossed_no_return: true,
        };
        let mut coordinator = InstallationCoordinator::new(KnownEffectPort { observation });

        let outcome =
            must(coordinator.apply(&mut transaction, InstallationEffectOperation::Activate));

        assert_eq!(
            outcome,
            InstallationStepOutcome::Applied {
                stage: InstallationStage::Activating,
                evidence_refs: vec![evidence],
            }
        );
        assert_eq!(transaction.stage, InstallationStage::Activating);
        assert_eq!(transaction.no_return_boundary.as_ref(), Some(&boundary));
        assert_eq!(transaction.revision, starting_revision + 1);
    }

    #[test]
    fn runtime_launch_descriptor_binds_exact_arguments_and_rejects_tampering() {
        let transaction = registering_transaction();
        let descriptor = &transaction.candidate_manifest.runtime_launch;
        assert_eq!(descriptor.kernel_arguments[0].as_str(), "--work-root");
        assert_eq!(descriptor.canonical_store_arguments[2].as_str(), "--config");
        assert!(descriptor.validate().is_ok());
        let config = &transaction.candidate_manifest.config_path;
        assert!(descriptor.validate_for_config(config).is_ok());

        let mut tampered = descriptor.clone();
        tampered.canonical_store_arguments[0] = test_handle("--outside-root");
        assert!(tampered.validate_for_config(config).is_err());

        let mut missing_config = descriptor.clone();
        missing_config.canonical_store_arguments.truncate(2);
        assert!(missing_config.validate_for_config(config).is_err());

        let mut duplicate_config = descriptor.clone();
        duplicate_config
            .canonical_store_arguments
            .push(test_handle(config.as_str()));
        assert!(duplicate_config.validate_for_config(config).is_err());

        let mut alternate_config = descriptor.clone();
        alternate_config.canonical_store_arguments[3] = test_path(
            &std::env::temp_dir(),
            "eliot-installation-alternate-config.json",
        );
        assert!(alternate_config.validate_for_config(config).is_err());

        let mut missing_root = descriptor.clone();
        missing_root.portable_root = None;
        assert!(missing_root.validate().is_err());
    }

    #[test]
    fn manifest_rejects_unbound_store_config_alias() {
        let mut manifest = registering_transaction().candidate_manifest;
        manifest.runtime_launch.store_config_path = test_handle(
            std::env::temp_dir()
                .join("eliot-installation-unbound-store.json")
                .to_string_lossy()
                .into_owned(),
        );
        let error = match manifest.validate() {
            Ok(()) => panic!("unbound Store config must fail closed"),
            Err(error) => error,
        };
        assert!(
            matches!(error, InstallationError::InvalidField { field, .. } if field == "manifest.runtime_launch.store_config_path")
        );
    }

    #[test]
    fn manifest_rejects_bridge_as_canonical_engine_and_aliased_paths() {
        let mut manifest = registering_transaction().candidate_manifest;
        manifest.canonical_store_executable_path = manifest.store_bridge_executable_path.clone();
        assert!(manifest.validate().is_err());

        let mut swapped = registering_transaction().candidate_manifest;
        swapped.canonical_store_executable_path =
            test_path(&std::env::temp_dir(), "wrong-canonical-engine.exe");
        assert!(swapped.validate().is_err());
    }
}
