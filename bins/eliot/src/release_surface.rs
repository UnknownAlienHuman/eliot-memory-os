#![forbid(unsafe_code)]

//! Immutable installed-release surface manifest (I19.8) and the read-only
//! Doctor comparison of one installed release.
//!
//! The release owner runs `eliot release surface-manifest` after
//! `eliot installation materialize-source-bundle` has published the exact
//! Phase-A source bundle and before `eliot installation apply` mutates the
//! machine. Generation hashes observed bytes only: it copies nothing, mutates
//! no observed installation, and publishes exactly one create-new manifest that
//! no later code path in this binary reopens for writing.
//!
//! `eliot doctor release-surface` opens the accepted manifest read-only,
//! re-hashes every declared installed artifact, re-reads the installed route
//! profile, and emits one typed `MATCH`/`MISSING`/`MISMATCH`/`STALE`/`UNKNOWN`
//! verdict per field. It reports drift only; a regenerate, repair, or re-sign
//! path does not exist in this module.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_bootstrap::capture::{SnapshotExecutionArtifact, capture_snapshot};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_installation::{
    GenerationPackagePlanner, InstallationEpoch, InstallationProfile, PackageArtifactDigest,
    PlatformHandle, SupervisionAuthorityBinding,
};
use eliot_platform_windows::{
    AuthenticodeEvidence, AuthenticodeVerifier, PackageFileSpec, PackageManifest,
    TrustedSourceBundle, WindowsAuthenticodeVerifier, file_identity_for_path,
    validate_package_relative_path,
};
use eliot_runtime_contracts::{
    RUNTIME_LIVE_STORE_BIND, RUNTIME_LIVE_STORE_ENDPOINT, RUNTIME_LIVE_STORE_NAMESPACE,
};
use eliot_store_surreal::{StoreLaunchConfig, launch_config_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::source_bundle_materializer::REQUIRED_ROLES;

/// Wire identity of the immutable installed-release surface manifest.
pub const MANIFEST_WIRE_ID: &str = "eliot.release-surface-manifest";
/// Wire schema version of the immutable installed-release surface manifest.
pub const MANIFEST_SCHEMA_VERSION: &str = "1.0.0";
/// Wire identity of the Doctor drift report.
pub const DRIFT_REPORT_CONTRACT: &str = "eliot.doctor.release-surface";
/// Wire schema version of the Doctor drift report.
pub const DRIFT_REPORT_CONTRACT_VERSION: &str = "1.0.0";
/// Bounded manifest envelope; a larger file is never parsed.
pub const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
/// Bounded bytes-per-file envelope for every observed release artifact.
pub const MAX_SURFACE_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// The nine source-built bundle binaries whose exact hashes one release binds
/// (`docs/release/CLAIM_BOUNDARY.md` nine-binary build scope).
pub const BUNDLE_BINARIES: [&str; 9] = [
    "eliot",
    "eliot-host",
    "eliot-watchdog",
    "eliot-kernel",
    "eliot-store-surreal",
    "eliotd",
    "eliot-doctor",
    "eliot-testd",
    "eliot-native-worker",
];
/// Release-bundle-relative location of the install-authoritative CLI binary.
const INSTALL_AUTHORITATIVE_CLI: &str = "runtime/eliot.exe";
/// Release-bundle-relative release receipt required by every release.
const RELEASE_RECEIPT: &str = "RELEASE.json";
/// Release-bundle-relative staged payload manifest required by every release.
const STAGED_PAYLOAD_MANIFEST: &str = "STAGED_PAYLOAD_MANIFEST.json";
/// Release-bundle-relative signing evidence present only after finalization.
const SIGNING_EVIDENCE: &str = "SIGNING_VERIFIED.json";
/// Repository-relative accepted normative-pair receipt.
const NORMATIVE_PAIR_REF: &str = "docs/normative-pair.toml";
/// Separator used when a list-valued field is compared as one exact string.
const LIST_SEPARATOR: char = '\u{1f}';
/// The exact ten I19.8 sections. The list is code-owned, so an operator-authored
/// manifest can neither add an unreviewed section nor drop a required one
/// without the removal becoming an observable `MISSING` verdict.
pub const REQUIRED_SECTIONS: [ReleaseSurfaceSection; 10] = [
    ReleaseSurfaceSection::ProductAndSourceIdentity,
    ReleaseSurfaceSection::ArchitectureAndImplementationDigests,
    ReleaseSurfaceSection::GeneratedSchemaPluginSkillHookAndPromptDigests,
    ReleaseSurfaceSection::InstalledCacheConfigRegistrationAndBridgeDigests,
    ReleaseSurfaceSection::ExecutablePackageRouteAndModuleGenerationDigests,
    ReleaseSurfaceSection::ActiveServiceProcessStoreAndUserBrokerFingerprints,
    ReleaseSurfaceSection::CapabilityAndGovernanceProfileRefs,
    ReleaseSurfaceSection::MigrationAndRollbackRefs,
    ReleaseSurfaceSection::InvalidationAndExpiry,
    ReleaseSurfaceSection::ReleaseReceiptAndSigningIdentity,
];

/// One I19.8 manifest section. The wire spelling is the exact I19.8 key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseSurfaceSection {
    /// `product_and_source_identity`.
    ProductAndSourceIdentity,
    /// `architecture_and_implementation_digests`.
    ArchitectureAndImplementationDigests,
    /// `generated_schema_plugin_skill_hook_and_prompt_digests`.
    GeneratedSchemaPluginSkillHookAndPromptDigests,
    /// `installed_cache_config_registration_and_bridge_digests`.
    InstalledCacheConfigRegistrationAndBridgeDigests,
    /// `executable_package_route_and_module_generation_digests`.
    ExecutablePackageRouteAndModuleGenerationDigests,
    /// `active_service_process_store_and_user_broker_fingerprints`.
    ActiveServiceProcessStoreAndUserBrokerFingerprints,
    /// `capability_and_governance_profile_refs`.
    CapabilityAndGovernanceProfileRefs,
    /// `migration_and_rollback_refs`.
    MigrationAndRollbackRefs,
    /// `invalidation_and_expiry`.
    InvalidationAndExpiry,
    /// `release_receipt_and_signing_identity`.
    ReleaseReceiptAndSigningIdentity,
}

impl ReleaseSurfaceSection {
    /// Exact I19.8 key of this section.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProductAndSourceIdentity => "product_and_source_identity",
            Self::ArchitectureAndImplementationDigests => "architecture_and_implementation_digests",
            Self::GeneratedSchemaPluginSkillHookAndPromptDigests => {
                "generated_schema_plugin_skill_hook_and_prompt_digests"
            }
            Self::InstalledCacheConfigRegistrationAndBridgeDigests => {
                "installed_cache_config_registration_and_bridge_digests"
            }
            Self::ExecutablePackageRouteAndModuleGenerationDigests => {
                "executable_package_route_and_module_generation_digests"
            }
            Self::ActiveServiceProcessStoreAndUserBrokerFingerprints => {
                "active_service_process_store_and_user_broker_fingerprints"
            }
            Self::CapabilityAndGovernanceProfileRefs => "capability_and_governance_profile_refs",
            Self::MigrationAndRollbackRefs => "migration_and_rollback_refs",
            Self::InvalidationAndExpiry => "invalidation_and_expiry",
            Self::ReleaseReceiptAndSigningIdentity => "release_receipt_and_signing_identity",
        }
    }
}

/// Typed per-field Doctor verdict. The four drift verdicts stay distinct across
/// every layer boundary and are never collapsed into one code or one message.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseSurfaceFieldVerdict {
    /// The observed identity equals the accepted manifest identity exactly.
    Match,
    /// A required manifest field, declared artifact, or observed artifact is
    /// absent.
    Missing,
    /// The observed identity diverges from the accepted manifest identity.
    Mismatch,
    /// The manifest no longer describes the observed surface.
    Stale,
    /// This front door has no observation port for the field.
    Unknown,
}

impl ReleaseSurfaceFieldVerdict {
    const fn is_drift(self) -> bool {
        !matches!(self, Self::Match)
    }
}

/// Terminal disposition of one Doctor release-surface comparison.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseSurfaceDisposition {
    /// Every required field was observed and matched.
    Verified,
    /// At least one required field drifted, was absent, or was unobservable.
    Drift,
}

/// One typed field-level Doctor finding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSurfaceFinding {
    /// I19.8 section the field belongs to.
    pub section: ReleaseSurfaceSection,
    /// Field name inside the section.
    pub field: String,
    /// Typed verdict for this exact field.
    pub verdict: ReleaseSurfaceFieldVerdict,
    /// Accepted manifest value, absent when the manifest field is absent.
    pub expected: Option<String>,
    /// Observed value, absent when nothing could be observed.
    pub observed: Option<String>,
    /// Bounded, non-authoritative triage detail.
    pub detail: String,
}

/// Per-verdict finding counts.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSurfaceVerdictCounts {
    /// Fields whose observed identity matched exactly.
    pub matched: usize,
    /// Required fields or artifacts that were absent.
    pub missing: usize,
    /// Fields whose observed identity diverged.
    pub mismatched: usize,
    /// Fields for which the manifest no longer describes the observation.
    pub stale: usize,
    /// Fields with no observation port in this front door.
    pub unknown: usize,
}

/// The complete Doctor release-surface drift report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSurfaceDriftReport {
    /// Report contract identity.
    pub contract: String,
    /// Report contract schema version.
    pub contract_version: String,
    /// Absolute path of the accepted manifest that was read.
    pub manifest_path: String,
    /// Lowercase SHA-256 of the manifest bytes observed before comparison.
    pub manifest_sha256_before: String,
    /// Lowercase SHA-256 of the manifest bytes observed after comparison.
    pub manifest_sha256_after: String,
    /// Whether the accepted manifest bytes stayed byte-identical across the
    /// whole comparison. Doctor never writes this file.
    pub manifest_bytes_unchanged: bool,
    /// Whether the manifest content digest reproduces from its own bytes.
    pub manifest_self_digest_verified: bool,
    /// Manifest content digest that Product Proof receipts and migration
    /// evidence snapshots must be bound to for this release.
    pub surface_digest: String,
    /// Release identity the accepted manifest declares, when present.
    pub release_id: Option<String>,
    /// Generation the accepted manifest declares, when present.
    pub generation: Option<String>,
    /// Every required section carried by the manifest, in I19.8 order.
    pub sections_present: Vec<ReleaseSurfaceSection>,
    /// Per-verdict finding counts.
    pub counts: ReleaseSurfaceVerdictCounts,
    /// Every field-level finding, ordered by section then field.
    pub findings: Vec<ReleaseSurfaceFinding>,
    /// Terminal disposition.
    pub disposition: ReleaseSurfaceDisposition,
    /// Doctor compared the accepted manifest and reported; it never
    /// regenerated, repaired, or re-signed it.
    pub manifest_mutated: bool,
    /// Observation instant used for expiry comparison, in Unix seconds.
    pub observed_at_unix_seconds: i64,
}

impl ReleaseSurfaceDriftReport {
    /// Whether the report carries any accepted drift.
    #[must_use]
    pub const fn drift_detected(&self) -> bool {
        matches!(self.disposition, ReleaseSurfaceDisposition::Drift)
    }
}

/// Materialization state of one installed cache/config/registration artifact.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseSurfaceMaterialization {
    /// The release bound the exact installed bytes. This is also the wire
    /// default for a field an accepted manifest omits, so an omitted
    /// materialization state still requires an exact digest before Doctor can
    /// report a match.
    #[default]
    Bound,
    /// The release bound a Phase-B descriptor that has no bytes yet; this front
    /// door has no observation port for it.
    PendingPhaseB,
}

/// One file-backed identity bound by the manifest.
#[derive(Default, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceFileFact {
    /// Logical fact name inside its section.
    pub name: String,
    /// Absolute path the fact must be observed at on the installed machine.
    pub installed_path: String,
    /// Release-bundle-relative path this fact was generated from, when the fact
    /// is a release-payload item.
    pub release_relative_path: Option<String>,
    /// Exact byte length of the generated artifact.
    pub size: u64,
    /// Lowercase SHA-256 of the exact generated bytes, absent only for a
    /// declared pending Phase-B descriptor.
    pub sha256: Option<String>,
    /// Materialization state of this artifact.
    pub materialization: ReleaseSurfaceMaterialization,
}

impl ReleaseSurfaceFileFact {
    fn bound(
        name: &str,
        installed_path: &Path,
        release_relative_path: Option<&str>,
        bytes: &[u8],
    ) -> Self {
        Self {
            name: name.to_owned(),
            installed_path: installed_path.to_string_lossy().into_owned(),
            release_relative_path: release_relative_path.map(str::to_owned),
            size: bytes.len() as u64,
            sha256: Some(sha256_hex(bytes)),
            materialization: ReleaseSurfaceMaterialization::Bound,
        }
    }

    fn pending(name: &str, installed_path: &Path) -> Self {
        Self {
            name: name.to_owned(),
            installed_path: installed_path.to_string_lossy().into_owned(),
            release_relative_path: None,
            size: 0,
            sha256: None,
            materialization: ReleaseSurfaceMaterialization::PendingPhaseB,
        }
    }
}

/// `product_and_source_identity`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceProductAndSourceIdentity {
    /// Product name bound by this release.
    pub product: Option<String>,
    /// Product package version bound by this release.
    pub product_version: Option<String>,
    /// Pinned 40-hex source commit this release was built from.
    pub source_commit: Option<String>,
    /// Canonical release source root the commit was read from.
    pub source_root: Option<String>,
    /// `CurrentSystemEvidenceSnapshot` digest captured from the same root.
    pub source_snapshot_sha256: Option<String>,
    /// Release receipt identity that authorized this generation.
    pub transaction_id: Option<PlatformHandle>,
    /// Installation identity this release is installed for.
    pub installation: Option<PlatformHandle>,
    /// Installation lineage identity.
    pub installation_lineage_id: Option<PlatformHandle>,
    /// Monotonic installation sequence within the lineage.
    pub installation_sequence: Option<u64>,
    /// Explicit installation profile.
    pub profile: Option<InstallationProfile>,
    /// Canonical relative package generation identity.
    pub generation: Option<PlatformHandle>,
}

/// `architecture_and_implementation_digests`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceArchitectureAndImplementationDigests {
    /// Repository-relative path of the accepted normative-pair receipt.
    pub normative_pair_ref: Option<String>,
    /// Architecture document digest from that receipt.
    pub architecture_sha256: Option<String>,
    /// Implementation document digest from that receipt.
    pub implementation_sha256: Option<String>,
}

/// `generated_schema_plugin_skill_hook_and_prompt_digests`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceGeneratedDigests {
    /// Generated schema artifacts shipped by this release.
    pub schemas: Option<Vec<ReleaseSurfaceFileFact>>,
    /// Generated plugin artifacts shipped by this release.
    pub plugins: Option<Vec<ReleaseSurfaceFileFact>>,
    /// Generated Skill artifacts shipped by this release.
    pub skills: Option<Vec<ReleaseSurfaceFileFact>>,
    /// Generated hook artifacts shipped by this release.
    pub hooks: Option<Vec<ReleaseSurfaceFileFact>>,
    /// Generated prompt artifacts shipped by this release.
    pub prompts: Option<Vec<ReleaseSurfaceFileFact>>,
}

/// `installed_cache_config_registration_and_bridge_digests`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceInstalledDigests {
    /// Installed Store/host configuration artifacts.
    pub config: Option<Vec<ReleaseSurfaceFileFact>>,
    /// Installed plugin/registration artifacts.
    pub registration: Option<Vec<ReleaseSurfaceFileFact>>,
    /// Installed cache and Phase-B descriptor references.
    pub cache: Option<Vec<ReleaseSurfaceFileFact>>,
    /// Installed bridge binaries.
    pub bridges: Option<Vec<ReleaseSurfaceFileFact>>,
}

/// The exact route profile one release binds, projected from the observed
/// installed `generation.json`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceRouteProfile {
    /// Installation profile.
    pub profile: Option<String>,
    /// Portable anchor root, when the profile is `portable_dev`.
    pub portable_root: Option<String>,
    /// Installation identity.
    pub installation: Option<String>,
    /// Installation lineage identity.
    pub installation_lineage_id: Option<String>,
    /// Installation sequence.
    pub installation_sequence: Option<u64>,
    /// Canonical package generation.
    pub generation: Option<String>,
    /// Authority generation carried by the approved handoff descriptor.
    pub authority_generation: Option<u64>,
    /// Authority state fence carried by the approved handoff descriptor.
    pub authority_state_fence: Option<String>,
    /// Authority descriptor path.
    pub authority_descriptor_path: Option<String>,
    /// Authority descriptor digest, or the Phase-B pending marker.
    pub authority_descriptor_digest: Option<String>,
    /// Supervision authority state discriminant.
    pub supervision_authority_state: Option<String>,
    /// Supervision lease scope identity.
    pub supervision_lease_scope_id: Option<String>,
    /// Runtime state roots digest.
    pub runtime_state_roots_digest: Option<String>,
    /// Installation root.
    pub installation_root: Option<String>,
    /// Host journal and supervision state root.
    pub host_state_root: Option<String>,
    /// Canonical Store data root.
    pub store_data_root: Option<String>,
    /// Kernel working directory.
    pub kernel_work_root: Option<String>,
    /// Kernel image digest.
    pub kernel_artifact_digest: Option<String>,
    /// Host image digest.
    pub host_artifact_digest: Option<String>,
    /// Watchdog image digest.
    pub watchdog_artifact_digest: Option<String>,
    /// Doctor image digest.
    pub doctor_artifact_digest: Option<String>,
    /// Testd image digest.
    pub testd_artifact_digest: Option<String>,
    /// Native worker image digest.
    pub native_worker_artifact_digest: Option<String>,
    /// WASM host image digest.
    pub wasm_host_artifact_digest: Option<String>,
    /// `eliotd` image digest.
    pub eliotd_artifact_digest: Option<String>,
    /// Store bridge image digest.
    pub store_bridge_artifact_digest: Option<String>,
    /// Canonical Store image digest.
    pub canonical_store_artifact_digest: Option<String>,
    /// Governor configuration descriptor digest.
    pub eliotd_config_digest: Option<String>,
    /// `eliotd` launch descriptor digest.
    pub eliotd_descriptor_digest: Option<String>,
    /// `eliotd` launch nonce.
    pub eliotd_launch_nonce: Option<String>,
    /// Protected Kernel/`eliotd` snapshot identity.
    pub protected_snapshot_digest: Option<String>,
    /// Runtime launch descriptor self-digest.
    pub runtime_launch_digest: Option<String>,
    /// Store configuration digest.
    pub store_config_digest: Option<String>,
    /// Installed Store configuration path.
    pub store_config_path: Option<String>,
    /// Store credential target.
    pub store_credential_target: Option<String>,
    /// Store schema generation.
    pub store_schema_generation: Option<String>,
    /// Canonical runtime-live Store bind address.
    pub live_store_bind: Option<String>,
    /// Canonical runtime-live Store endpoint.
    pub live_store_endpoint: Option<String>,
    /// Canonical runtime-live Store namespace.
    pub live_store_namespace: Option<String>,
    /// Store database name.
    pub live_store_database: Option<String>,
    /// Exact Kernel launch arguments.
    pub kernel_arguments: Option<Vec<String>>,
    /// Exact Store bridge launch arguments.
    pub store_bridge_arguments: Option<Vec<String>>,
    /// Exact canonical Store launch arguments.
    pub canonical_store_arguments: Option<Vec<String>>,
}

/// `executable_package_route_and_module_generation_digests`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceExecutablePackageRouteDigests {
    /// Exact hashes of the nine source-built bundle binaries.
    pub bundle_binaries: Option<Vec<ReleaseSurfaceFileFact>>,
    /// Exact hashes of every published Phase-A executable role.
    pub phase_a_executables: Option<Vec<ReleaseSurfaceFileFact>>,
    /// Canonical `PackageManifest` digest of the published Phase-A bundle.
    pub phase_a_package_manifest_digest: Option<String>,
    /// Canonical artifact-set evidence digest of the published Phase-A bundle.
    pub phase_a_evidence_digest: Option<String>,
    /// Canonical Phase-A template content digest.
    pub phase_a_template_content_digest: Option<String>,
    /// Exact route profile bound by this release.
    pub route_profile: Option<ReleaseSurfaceRouteProfile>,
}

/// `active_service_process_store_and_user_broker_fingerprints`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceRuntimeFingerprints {
    /// Active runtime generation the route profile binds.
    pub active_runtime_generation: Option<String>,
    /// Authority generation the route profile binds.
    pub authority_generation: Option<u64>,
    /// Supervision lease scope identity the route profile binds.
    pub supervision_lease_scope_id: Option<String>,
    /// Runtime state roots digest the route profile binds.
    pub runtime_state_roots_digest: Option<String>,
    /// Canonical runtime-live Store identity.
    pub live_store_identity: Option<String>,
    /// Store credential target.
    pub store_credential_target: Option<String>,
    /// Protected Kernel/`eliotd` snapshot identity.
    pub protected_snapshot_digest: Option<String>,
    /// Per-user Notify adapter image digest this release binds.
    pub user_broker_notify_artifact_digest: Option<String>,
    /// Service and process liveness. This read-only comparison has no
    /// observation port for liveness, so the release never populates it.
    pub process_liveness: Option<String>,
}

/// `capability_and_governance_profile_refs`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceCapabilityAndGovernanceRefs {
    /// Installed Governor launch configuration descriptor.
    pub governance_profile: Option<ReleaseSurfaceFileFact>,
    /// Capability-cell registry artifacts bound by this release.
    pub capability_cell_registries: Option<Vec<ReleaseSurfaceFileFact>>,
}

/// `migration_and_rollback_refs`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceMigrationAndRollbackRefs {
    /// Exact recovery/rollback command retained by the release transaction.
    pub rollback_command: Option<PlatformHandle>,
    /// Digest of the superseded release manifest this release rolls forward
    /// from.
    pub supersedes_manifest_sha256: Option<String>,
    /// Prior generation retained as the rollback target.
    pub prior_generation: Option<PlatformHandle>,
    /// Release-scoped migration evidence snapshots bound by this manifest.
    pub migration_evidence_snapshots: Option<Vec<ReleaseSurfaceFileFact>>,
    /// Release-scoped Product Proof receipts bound by this manifest.
    pub product_proof_receipts: Option<Vec<ReleaseSurfaceFileFact>>,
}

/// `invalidation_and_expiry`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceInvalidationAndExpiry {
    /// Generation instant of this manifest, in Unix seconds.
    pub generated_at_unix_seconds: Option<i64>,
    /// Instant after which this manifest no longer describes its release, in
    /// Unix seconds.
    pub expires_at_unix_seconds: Option<i64>,
    /// Every condition that invalidates this manifest for an installed surface.
    pub invalidated_by: Option<Vec<String>>,
}

/// One Authenticode signing identity bound by the release.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceSigningIdentity {
    /// Release role the signature belongs to.
    pub role: String,
    /// `WinTrust` verdict for those exact bytes.
    pub verdict: String,
    /// Leaf signer certificate SHA-256, when the provider exposed it.
    pub signer_certificate_sha256: Option<String>,
    /// Leaf signer subject, when exposed.
    pub signer_subject: Option<String>,
    /// Leaf certificate validity start, when exposed.
    pub signer_not_before_unix_seconds: Option<i64>,
    /// Leaf certificate expiry, when exposed.
    pub signer_not_after_unix_seconds: Option<i64>,
    /// Primary countersigner certificate SHA-256, when exposed.
    pub countersigner_certificate_sha256: Option<String>,
    /// Raw `WinTrust` status.
    pub trust_status: u32,
}

impl ReleaseSurfaceSigningIdentity {
    fn from_evidence(role: &str, evidence: &AuthenticodeEvidence) -> Self {
        Self {
            role: role.to_owned(),
            verdict: format!("{:?}", evidence.verdict),
            signer_certificate_sha256: evidence.signer_certificate_sha256.clone(),
            signer_subject: evidence.signer_subject.clone(),
            signer_not_before_unix_seconds: evidence.signer_not_before_unix_seconds,
            signer_not_after_unix_seconds: evidence.signer_not_after_unix_seconds,
            countersigner_certificate_sha256: evidence.countersigner_certificate_sha256.clone(),
            trust_status: evidence.trust_status,
        }
    }
}

/// `release_receipt_and_signing_identity`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceReceiptAndSigningIdentity {
    /// Release-scoped release receipt bound by this manifest.
    pub release_receipt: Option<ReleaseSurfaceFileFact>,
    /// Release-scoped staged payload manifest bound by this manifest.
    pub staged_payload_manifest: Option<ReleaseSurfaceFileFact>,
    /// Release-scoped signing evidence, present only for a finalized bundle.
    pub signing_evidence: Option<ReleaseSurfaceFileFact>,
    /// Exact Authenticode signing identity per released bundle binary.
    pub signing_identities: Option<Vec<ReleaseSurfaceSigningIdentity>>,
}

/// The complete immutable installed-release surface manifest.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseSurfaceManifest {
    /// Manifest wire identity.
    pub wire_id: Option<String>,
    /// Manifest schema version.
    pub schema_version: Option<String>,
    /// Content digest of every preceding field, computed with this field empty.
    /// Product Proof receipts and migration evidence snapshots bind to it.
    pub surface_digest: Option<String>,
    /// Release identity derived from the pinned source commit and the
    /// installable generation.
    pub release_id: Option<String>,
    /// `product_and_source_identity`.
    pub product_and_source_identity: Option<ReleaseSurfaceProductAndSourceIdentity>,
    /// `architecture_and_implementation_digests`.
    pub architecture_and_implementation_digests:
        Option<ReleaseSurfaceArchitectureAndImplementationDigests>,
    /// `generated_schema_plugin_skill_hook_and_prompt_digests`.
    pub generated_schema_plugin_skill_hook_and_prompt_digests:
        Option<ReleaseSurfaceGeneratedDigests>,
    /// `installed_cache_config_registration_and_bridge_digests`.
    pub installed_cache_config_registration_and_bridge_digests:
        Option<ReleaseSurfaceInstalledDigests>,
    /// `executable_package_route_and_module_generation_digests`.
    pub executable_package_route_and_module_generation_digests:
        Option<ReleaseSurfaceExecutablePackageRouteDigests>,
    /// `active_service_process_store_and_user_broker_fingerprints`.
    pub active_service_process_store_and_user_broker_fingerprints:
        Option<ReleaseSurfaceRuntimeFingerprints>,
    /// `capability_and_governance_profile_refs`.
    pub capability_and_governance_profile_refs: Option<ReleaseSurfaceCapabilityAndGovernanceRefs>,
    /// `migration_and_rollback_refs`.
    pub migration_and_rollback_refs: Option<ReleaseSurfaceMigrationAndRollbackRefs>,
    /// `invalidation_and_expiry`.
    pub invalidation_and_expiry: Option<ReleaseSurfaceInvalidationAndExpiry>,
    /// `release_receipt_and_signing_identity`.
    pub release_receipt_and_signing_identity: Option<ReleaseSurfaceReceiptAndSigningIdentity>,
}

impl ReleaseSurfaceManifest {
    /// Content digest of the manifest with [`Self::surface_digest`] empty,
    /// recomputed from the accepted bytes.
    fn compute_surface_digest(&self) -> Result<String, ReleaseSurfaceError> {
        let mut unsigned = self.clone();
        unsigned.surface_digest = None;
        let bytes = canonical_json_bytes(&unsigned)
            .map_err(|error| ReleaseSurfaceError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Whether the manifest carries the requested I19.8 section.
    #[must_use]
    pub fn carries(&self, section: ReleaseSurfaceSection) -> bool {
        match section {
            ReleaseSurfaceSection::ProductAndSourceIdentity => {
                self.product_and_source_identity.is_some()
            }
            ReleaseSurfaceSection::ArchitectureAndImplementationDigests => {
                self.architecture_and_implementation_digests.is_some()
            }
            ReleaseSurfaceSection::GeneratedSchemaPluginSkillHookAndPromptDigests => self
                .generated_schema_plugin_skill_hook_and_prompt_digests
                .is_some(),
            ReleaseSurfaceSection::InstalledCacheConfigRegistrationAndBridgeDigests => self
                .installed_cache_config_registration_and_bridge_digests
                .is_some(),
            ReleaseSurfaceSection::ExecutablePackageRouteAndModuleGenerationDigests => self
                .executable_package_route_and_module_generation_digests
                .is_some(),
            ReleaseSurfaceSection::ActiveServiceProcessStoreAndUserBrokerFingerprints => self
                .active_service_process_store_and_user_broker_fingerprints
                .is_some(),
            ReleaseSurfaceSection::CapabilityAndGovernanceProfileRefs => {
                self.capability_and_governance_profile_refs.is_some()
            }
            ReleaseSurfaceSection::MigrationAndRollbackRefs => {
                self.migration_and_rollback_refs.is_some()
            }
            ReleaseSurfaceSection::InvalidationAndExpiry => self.invalidation_and_expiry.is_some(),
            ReleaseSurfaceSection::ReleaseReceiptAndSigningIdentity => {
                self.release_receipt_and_signing_identity.is_some()
            }
        }
    }

    /// Installed Store configuration path the accepted manifest declares, used
    /// by Doctor to re-read the observed route profile.
    #[must_use]
    pub fn declared_store_config_path(&self) -> Option<PathBuf> {
        self.executable_package_route_and_module_generation_digests
            .as_ref()?
            .route_profile
            .as_ref()?
            .store_config_path
            .as_ref()
            .map(|value| PathBuf::from(value.as_str()))
    }
}

/// Fail-closed release-surface manifest errors.
#[derive(Debug, Error)]
pub enum ReleaseSurfaceError {
    /// An input path or value violates the manifest contract.
    #[error("release surface {field}: {reason}")]
    Invalid {
        /// Offending input field.
        field: &'static str,
        /// Exact reason the field was rejected.
        reason: String,
    },
    /// A required input was not supplied.
    #[error("release surface {field} is required: {reason}")]
    Required {
        /// Missing required input.
        field: &'static str,
        /// Why the input cannot be defaulted.
        reason: &'static str,
    },
    /// The filesystem boundary failed.
    #[error("release surface I/O for {path}: {detail}")]
    Io {
        /// Path that failed.
        path: String,
        /// Underlying detail.
        detail: String,
    },
    /// A typed contract rejected the request.
    #[error("release surface typed contract rejected: {0}")]
    Contract(String),
    /// The observed source tree was not the pinned release commit.
    #[error("release surface source tree is not the pinned release commit: {0}")]
    DirtySourceTree(String),
    /// The manifest bytes could not be encoded or decoded.
    #[error("release surface serialization failed: {0}")]
    Serialization(String),
    /// The create-new manifest destination already exists.
    #[error("release surface manifest already exists and is immutable: {0}")]
    ManifestExists(PathBuf),
    /// The published bytes did not read back identically.
    #[error("release surface manifest readback differs from the published bytes: {0}")]
    ManifestReadback(String),
}

fn require_absolute(path: &Path, field: &'static str) -> Result<(), ReleaseSurfaceError> {
    if !path.is_absolute() {
        return Err(ReleaseSurfaceError::Invalid {
            field,
            reason: "must be absolute".to_owned(),
        });
    }
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if lower.starts_with("\\\\?\\") || lower.starts_with("\\\\.\\") {
        return Err(ReleaseSurfaceError::Invalid {
            field,
            reason: "must not use a device or extended-length prefix".to_owned(),
        });
    }
    Ok(())
}

fn read_bounded(
    path: &Path,
    field: &'static str,
    limit: u64,
) -> Result<Vec<u8>, ReleaseSurfaceError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| ReleaseSurfaceError::Io {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    if !metadata.is_file() {
        return Err(ReleaseSurfaceError::Invalid {
            field,
            reason: format!("{} is not a regular file", path.display()),
        });
    }
    if metadata.len() > limit {
        return Err(ReleaseSurfaceError::Invalid {
            field,
            reason: format!("{} exceeds the {limit}-byte bound", path.display()),
        });
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| ReleaseSurfaceError::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ReleaseSurfaceError::Io {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
    if bytes.len() as u64 > limit {
        return Err(ReleaseSurfaceError::Invalid {
            field,
            reason: format!("{} exceeds the {limit}-byte bound", path.display()),
        });
    }
    Ok(bytes)
}

fn current_unix_seconds() -> Result<i64, ReleaseSurfaceError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ReleaseSurfaceError::Contract(format!("system clock: {error}")))?;
    i64::try_from(elapsed.as_secs())
        .map_err(|_| ReleaseSurfaceError::Contract("system clock is out of range".to_owned()))
}

fn joined_list(values: &[String]) -> String {
    let mut joined = String::new();
    for value in values {
        let _ = write!(joined, "{LIST_SEPARATOR}{value}");
    }
    joined
}

fn observed_file_digest(path: &Path) -> Result<Option<(u64, String)>, ReleaseSurfaceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Err(ReleaseSurfaceError::Invalid {
                field: "observed artifact",
                reason: format!("{} is not a regular file", path.display()),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ReleaseSurfaceError::Io {
                path: path.display().to_string(),
                detail: error.to_string(),
            });
        }
    }
    let bytes = read_bounded(path, "observed artifact", MAX_SURFACE_FILE_BYTES)?;
    Ok(Some((bytes.len() as u64, sha256_hex(&bytes))))
}

/// Explicit inputs for one immutable release-surface manifest.
#[derive(Clone, Debug)]
pub struct ReleaseSurfaceGenerateInput {
    /// Absolute release source root; the pinned commit and normative pair are
    /// read from it.
    pub repo_root: PathBuf,
    /// Absolute staged or finalized release bundle root.
    pub release_bundle: PathBuf,
    /// Absolute published Phase-A source bundle produced by
    /// `installation materialize-source-bundle`.
    pub phase_a_bundle: PathBuf,
    /// Absolute Phase-A generation destination root.
    pub phase_a_install_root: PathBuf,
    /// Absolute release payload destination root.
    pub release_install_root: PathBuf,
    /// Canonical relative package generation identity.
    pub generation: PlatformHandle,
    /// Installation identity.
    pub installation: PlatformHandle,
    /// Installation lineage identity.
    pub lineage_id: PlatformHandle,
    /// Monotonic installation sequence within the lineage.
    pub sequence: u64,
    /// Release receipt identity that authorized this generation.
    pub transaction_id: PlatformHandle,
    /// Explicit installation profile.
    pub profile: InstallationProfile,
    /// Exact recovery/rollback command retained by the release transaction.
    pub recovery_command: PlatformHandle,
    /// Instant after which this manifest no longer describes its release.
    pub expires_at_unix_seconds: i64,
    /// Release-bundle-relative generated schema artifacts; at least one.
    pub generated_schemas: Vec<String>,
    /// Release-bundle-relative generated plugin artifacts; at least one.
    pub generated_plugins: Vec<String>,
    /// Release-bundle-relative generated Skill artifacts; at least one.
    pub generated_skills: Vec<String>,
    /// Release-bundle-relative generated hook artifacts; at least one.
    pub generated_hooks: Vec<String>,
    /// Release-bundle-relative generated prompt artifacts; at least one.
    pub generated_prompts: Vec<String>,
    /// Repository-relative capability-cell registry artifacts; at least one.
    pub capability_cell_registries: Vec<String>,
    /// Release-scoped Product Proof receipt artifacts bound by this manifest.
    pub product_proof_receipts: Vec<PathBuf>,
    /// Release-scoped migration evidence snapshot artifacts bound by this
    /// manifest.
    pub migration_evidence_snapshots: Vec<PathBuf>,
    /// Manifest this release rolls forward from.
    pub supersedes: Option<PathBuf>,
    /// Prior generation retained as the rollback target.
    pub prior_generation: Option<PlatformHandle>,
    /// Absolute create-new manifest destination.
    pub output: PathBuf,
}

struct ObservedPhaseABundle {
    files: BTreeMap<String, (u64, String)>,
    package_manifest_digest: String,
    evidence_digest: String,
    template_digest: String,
    store_config: StoreLaunchConfig,
}

fn observe_phase_a_bundle(
    phase_a_bundle: &Path,
    generation: &PlatformHandle,
) -> Result<ObservedPhaseABundle, ReleaseSurfaceError> {
    let bundle = TrustedSourceBundle::open(phase_a_bundle).map_err(|error| {
        ReleaseSurfaceError::Contract(format!("open Phase-A source bundle: {error}"))
    })?;
    let observation = bundle.observe().map_err(|error| {
        ReleaseSurfaceError::Contract(format!("observe Phase-A bundle: {error}"))
    })?;
    if observation.files.len() != REQUIRED_ROLES.len() {
        return Err(ReleaseSurfaceError::Invalid {
            field: "phase_a_bundle",
            reason: format!(
                "published bundle carries {} files; the exact {}-role Phase-A inventory is required",
                observation.files.len(),
                REQUIRED_ROLES.len()
            ),
        });
    }
    let mut files: BTreeMap<String, (u64, String)> = BTreeMap::new();
    for file in &observation.files {
        files.insert(file.relative_path.clone(), (file.size, file.sha256.clone()));
    }
    let mut specs = Vec::with_capacity(REQUIRED_ROLES.len());
    let mut expected = Vec::with_capacity(REQUIRED_ROLES.len());
    for (role, executable) in REQUIRED_ROLES {
        let (size, digest) = files
            .get(role)
            .ok_or_else(|| ReleaseSurfaceError::Invalid {
                field: "phase_a_bundle",
                reason: format!("published role missing: {role}"),
            })?;
        specs.push(
            PackageFileSpec::new(role, executable, *size)
                .map_err(|error| ReleaseSurfaceError::Contract(error.to_string()))?,
        );
        expected.push(PackageArtifactDigest {
            relative_path: role.to_owned(),
            expected_size: *size,
            sha256: PlatformHandle::new(digest.clone()).map_err(|error| {
                ReleaseSurfaceError::Contract(format!("published role digest {role}: {error}"))
            })?,
        });
    }
    let manifest = PackageManifest::new(Path::new(generation.as_str()), specs)
        .map_err(|error| ReleaseSurfaceError::Contract(error.to_string()))?;
    let evidence_digest =
        GenerationPackagePlanner::artifact_set_evidence_digest(&manifest, &expected)
            .map_err(|error| ReleaseSurfaceError::Contract(error.to_string()))?
            .as_str()
            .to_owned();
    let template_digest = GenerationPackagePlanner::phase_a_template_content_digest(&expected)
        .map_err(|error| ReleaseSurfaceError::Contract(error.to_string()))?
        .as_str()
        .to_owned();
    let config_bytes = read_bounded(
        &phase_a_bundle.join("generation.json"),
        "phase_a_bundle",
        MAX_SURFACE_FILE_BYTES,
    )?;
    let store_config: StoreLaunchConfig =
        serde_json::from_slice(&config_bytes).map_err(|error| {
            ReleaseSurfaceError::Contract(format!("parse published generation.json: {error}"))
        })?;
    Ok(ObservedPhaseABundle {
        files,
        package_manifest_digest: manifest.canonical_digest(),
        evidence_digest,
        template_digest,
        store_config,
    })
}

fn supervision_authority_facts(binding: &SupervisionAuthorityBinding) -> (String, String) {
    match binding {
        SupervisionAuthorityBinding::Pending {
            supervision_lease_scope_id,
        } => (
            "pending".to_owned(),
            supervision_lease_scope_id.as_str().to_owned(),
        ),
        SupervisionAuthorityBinding::Provisioned { authority } => (
            "provisioned".to_owned(),
            authority.supervision_lease_scope_id.as_str().to_owned(),
        ),
    }
}

fn handle_text(value: &PlatformHandle) -> String {
    value.as_str().to_owned()
}

fn handle_list_text(values: &[PlatformHandle]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect()
}

fn profile_text(profile: InstallationProfile) -> String {
    match profile {
        InstallationProfile::SystemService => "system_service".to_owned(),
        InstallationProfile::UserMode => "user_mode".to_owned(),
        InstallationProfile::PortableDev => "portable_dev".to_owned(),
    }
}

fn live_store_identity_text(route: &ReleaseSurfaceRouteProfile) -> String {
    [
        route.live_store_bind.clone().unwrap_or_default(),
        route.live_store_endpoint.clone().unwrap_or_default(),
        route.live_store_namespace.clone().unwrap_or_default(),
        route.live_store_database.clone().unwrap_or_default(),
    ]
    .join(&LIST_SEPARATOR.to_string())
}

/// Route-profile projection failure; kept distinct from input errors so a
/// malformed installed configuration never becomes a collapsed message.
#[derive(Debug, Error)]
enum ReleaseSourceProfileError {
    /// A typed route or Store contract rejected the observed configuration.
    #[error("route profile contract rejected: {0}")]
    Contract(String),
    /// The observed configuration could not be encoded canonically.
    #[error("route profile serialization failed: {0}")]
    Serialization(String),
}

fn route_profile_from_store_config(
    config: &StoreLaunchConfig,
) -> Result<ReleaseSurfaceRouteProfile, ReleaseSourceProfileError> {
    let launch = &config.runtime_launch;
    let (supervision_authority_state, supervision_lease_scope_id) =
        supervision_authority_facts(&launch.supervision_authority);
    let fence_digest = sha256_hex(
        &canonical_json_bytes(&launch.authority_state_fence)
            .map_err(|error| ReleaseSourceProfileError::Serialization(error.to_string()))?,
    );
    let config_digest =
        launch_config_digest(config).map_err(ReleaseSourceProfileError::Contract)?;
    let launch_digest = launch
        .compute_digest()
        .map_err(|error| ReleaseSourceProfileError::Contract(error.to_string()))?
        .as_str()
        .to_owned();
    Ok(ReleaseSurfaceRouteProfile {
        profile: Some(profile_text(launch.profile)),
        portable_root: launch
            .portable_root
            .as_ref()
            .map(|value| value.as_str().to_owned()),
        installation: Some(handle_text(&launch.installation_epoch.installation)),
        installation_lineage_id: Some(handle_text(&launch.installation_epoch.lineage_id)),
        installation_sequence: Some(launch.installation_epoch.sequence),
        generation: Some(handle_text(&launch.generation)),
        authority_generation: Some(launch.authority_generation.value()),
        authority_state_fence: Some(fence_digest),
        authority_descriptor_path: Some(handle_text(&launch.authority_descriptor_path)),
        authority_descriptor_digest: Some(handle_text(&launch.authority_descriptor_digest)),
        supervision_authority_state: Some(supervision_authority_state),
        supervision_lease_scope_id: Some(supervision_lease_scope_id),
        runtime_state_roots_digest: Some(handle_text(&launch.runtime_state_roots.roots_digest)),
        installation_root: Some(handle_text(&launch.runtime_state_roots.installation_root)),
        host_state_root: Some(handle_text(&launch.runtime_state_roots.host_state_root)),
        store_data_root: Some(handle_text(&launch.runtime_state_roots.store_data_root)),
        kernel_work_root: Some(handle_text(&launch.kernel_work_root)),
        kernel_artifact_digest: Some(handle_text(&launch.kernel_artifact_digest)),
        host_artifact_digest: Some(handle_text(&launch.host_artifact_digest)),
        watchdog_artifact_digest: Some(handle_text(&launch.watchdog_artifact_digest)),
        doctor_artifact_digest: Some(handle_text(&launch.doctor_artifact_digest)),
        testd_artifact_digest: Some(handle_text(&launch.testd_artifact_digest)),
        native_worker_artifact_digest: Some(handle_text(&launch.native_worker_artifact_digest)),
        wasm_host_artifact_digest: Some(handle_text(&launch.wasm_host_artifact_digest)),
        eliotd_artifact_digest: Some(handle_text(&launch.eliotd_artifact_digest)),
        store_bridge_artifact_digest: Some(handle_text(&launch.store_bridge_artifact_digest)),
        canonical_store_artifact_digest: Some(handle_text(&launch.canonical_store_artifact_digest)),
        eliotd_config_digest: Some(handle_text(&launch.eliotd_config_digest)),
        eliotd_descriptor_digest: Some(handle_text(&launch.eliotd_descriptor_digest)),
        eliotd_launch_nonce: Some(handle_text(&launch.eliotd_launch_nonce)),
        protected_snapshot_digest: Some(handle_text(&launch.protected_snapshot_digest)),
        runtime_launch_digest: Some(launch_digest),
        store_config_digest: Some(if config.approved_config_hash.is_empty() {
            config_digest
        } else {
            config.approved_config_hash.clone()
        }),
        store_config_path: Some(handle_text(&launch.store_config_path)),
        store_credential_target: Some(handle_text(&launch.store_credential_target)),
        store_schema_generation: Some(config.schema_generation.clone()),
        live_store_bind: Some(RUNTIME_LIVE_STORE_BIND.to_owned()),
        live_store_endpoint: Some(RUNTIME_LIVE_STORE_ENDPOINT.to_owned()),
        live_store_namespace: Some(RUNTIME_LIVE_STORE_NAMESPACE.to_owned()),
        live_store_database: Some(config.database.clone()),
        kernel_arguments: Some(handle_list_text(&launch.kernel_arguments)),
        store_bridge_arguments: Some(handle_list_text(&launch.store_bridge_arguments)),
        canonical_store_arguments: Some(handle_list_text(&launch.canonical_store_arguments)),
    })
}

fn validate_relative(relative_path: &str, field: &'static str) -> Result<(), ReleaseSurfaceError> {
    validate_package_relative_path(Path::new(relative_path)).map_err(|error| {
        ReleaseSurfaceError::Invalid {
            field,
            reason: format!("{relative_path}: {error}"),
        }
    })?;
    Ok(())
}

fn require_non_empty(values: &[String], field: &'static str) -> Result<(), ReleaseSurfaceError> {
    if values.is_empty() {
        return Err(ReleaseSurfaceError::Required {
            field,
            reason: "the I19.8 manifest binds at least one artifact of this kind; a release that \
                     ships none cannot publish a complete surface",
        });
    }
    Ok(())
}

fn phase_a_fact(
    name: &str,
    install_root: &Path,
    role: &str,
    files: &BTreeMap<String, (u64, String)>,
) -> Result<ReleaseSurfaceFileFact, ReleaseSurfaceError> {
    let (size, digest) = files
        .get(role)
        .ok_or_else(|| ReleaseSurfaceError::Invalid {
            field: "phase_a_bundle",
            reason: format!("published role missing: {role}"),
        })?;
    Ok(ReleaseSurfaceFileFact {
        name: name.to_owned(),
        installed_path: install_root.join(role).to_string_lossy().into_owned(),
        release_relative_path: None,
        size: *size,
        sha256: Some(digest.clone()),
        materialization: ReleaseSurfaceMaterialization::Bound,
    })
}

fn release_payload_fact(
    input: &ReleaseSurfaceGenerateInput,
    name: &str,
    relative_path: &str,
) -> Result<ReleaseSurfaceFileFact, ReleaseSurfaceError> {
    validate_relative(relative_path, "generated surface")?;
    let bytes = read_bounded(
        &input.release_bundle.join(relative_path),
        "generated surface",
        MAX_SURFACE_FILE_BYTES,
    )?;
    Ok(ReleaseSurfaceFileFact::bound(
        name,
        &input.release_install_root.join(relative_path),
        Some(relative_path),
        &bytes,
    ))
}

fn release_receipt_fact(
    input: &ReleaseSurfaceGenerateInput,
    name: &str,
    relative_path: &str,
    required: bool,
) -> Result<Option<ReleaseSurfaceFileFact>, ReleaseSurfaceError> {
    let source = input.release_bundle.join(relative_path);
    match fs::symlink_metadata(&source) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Err(ReleaseSurfaceError::Invalid {
                field: "release receipt",
                reason: format!("{} is not a regular file", source.display()),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => {
            return Ok(None);
        }
        Err(error) => {
            return Err(ReleaseSurfaceError::Io {
                path: source.display().to_string(),
                detail: error.to_string(),
            });
        }
    }
    let bytes = read_bounded(&source, "release receipt", MAX_SURFACE_FILE_BYTES)?;
    Ok(Some(ReleaseSurfaceFileFact::bound(
        name,
        &input.release_install_root.join(relative_path),
        Some(relative_path),
        &bytes,
    )))
}

fn repo_relative_fact(
    input: &ReleaseSurfaceGenerateInput,
    name: &str,
    relative_path: &str,
) -> Result<ReleaseSurfaceFileFact, ReleaseSurfaceError> {
    validate_relative(relative_path, "capability_cell_registries")?;
    let bytes = read_bounded(
        &input.repo_root.join(relative_path),
        "capability_cell_registries",
        MAX_SURFACE_FILE_BYTES,
    )?;
    Ok(ReleaseSurfaceFileFact::bound(
        name,
        &input.repo_root.join(relative_path),
        Some(relative_path),
        &bytes,
    ))
}

fn evidence_fact(name: &str, path: &Path) -> Result<ReleaseSurfaceFileFact, ReleaseSurfaceError> {
    require_absolute(path, "evidence")?;
    let bytes = read_bounded(path, "evidence", MAX_SURFACE_FILE_BYTES)?;
    Ok(ReleaseSurfaceFileFact::bound(name, path, None, &bytes))
}

fn release_payload_facts(
    input: &ReleaseSurfaceGenerateInput,
    prefix: &str,
    relatives: &[String],
) -> Result<Vec<ReleaseSurfaceFileFact>, ReleaseSurfaceError> {
    relatives
        .iter()
        .enumerate()
        .map(|(index, relative)| {
            release_payload_fact(input, &format!("{prefix}_{index}"), relative)
        })
        .collect()
}

fn signing_identity_for(
    path: &Path,
    role: &str,
    digest: &str,
) -> Result<ReleaseSurfaceSigningIdentity, ReleaseSurfaceError> {
    let identity = file_identity_for_path(path)
        .map_err(|error| ReleaseSurfaceError::Contract(format!("file identity: {error}")))?;
    let evidence = WindowsAuthenticodeVerifier
        .verify(path, identity, digest)
        .map_err(|error| {
            ReleaseSurfaceError::Contract(format!("Authenticode evidence for {role}: {error}"))
        })?;
    Ok(ReleaseSurfaceSigningIdentity::from_evidence(
        role, &evidence,
    ))
}

/// What the installed surface actually shows for the bound route profile.
///
/// A tampered or absent installed Store configuration is `Divergent`, not a
/// process error: the bound route profile is real evidence and its loss must
/// read as drift.
enum ObservedRoute {
    /// The installed Store configuration projected to the exact route profile.
    Projected(Box<ReleaseSurfaceRouteProfile>),
    /// The declared installed route profile is absent or does not project.
    Divergent(String),
    /// The accepted manifest declares no installed Store configuration path.
    Unavailable,
}

impl ObservedRoute {
    fn projected(&self) -> Option<&ReleaseSurfaceRouteProfile> {
        match self {
            Self::Projected(route) => Some(route.as_ref()),
            Self::Divergent(_) | Self::Unavailable => None,
        }
    }
}

fn observed_route_profile(manifest: &ReleaseSurfaceManifest) -> ObservedRoute {
    let Some(store_config_path) = manifest.declared_store_config_path() else {
        return ObservedRoute::Unavailable;
    };
    let bytes = match fs::read(&store_config_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ObservedRoute::Divergent(format!(
                "the installed Store configuration {} named by the manifest is absent",
                store_config_path.display()
            ));
        }
        Err(error) => {
            return ObservedRoute::Divergent(format!(
                "the installed Store configuration {} could not be read: {error}",
                store_config_path.display()
            ));
        }
    };
    let config: StoreLaunchConfig = match serde_json::from_slice(&bytes) {
        Ok(config) => config,
        Err(error) => {
            return ObservedRoute::Divergent(format!(
                "the installed Store configuration {} is not a valid launch configuration: {error}",
                store_config_path.display()
            ));
        }
    };
    match route_profile_from_store_config(&config) {
        Ok(route) => ObservedRoute::Projected(Box::new(route)),
        Err(error) => ObservedRoute::Divergent(format!(
            "the installed Store configuration {} does not project to a valid route profile: \
             {error}",
            store_config_path.display()
        )),
    }
}

fn runtime_fingerprints(
    route: &ReleaseSurfaceRouteProfile,
    phase_a: &ObservedPhaseABundle,
) -> ReleaseSurfaceRuntimeFingerprints {
    ReleaseSurfaceRuntimeFingerprints {
        active_runtime_generation: route.generation.clone(),
        authority_generation: route.authority_generation,
        supervision_lease_scope_id: route.supervision_lease_scope_id.clone(),
        runtime_state_roots_digest: route.runtime_state_roots_digest.clone(),
        live_store_identity: Some(live_store_identity_text(route)),
        store_credential_target: route.store_credential_target.clone(),
        protected_snapshot_digest: route.protected_snapshot_digest.clone(),
        user_broker_notify_artifact_digest: phase_a
            .files
            .get("eliot-notify.exe")
            .map(|(_, digest)| digest.clone()),
        process_liveness: None,
    }
}

/// Build the manifest from observed release bytes without publishing it.
#[allow(
    clippy::too_many_lines,
    reason = "one fail-closed release-generation boundary keeps every observation next to the section it binds"
)]
fn build_manifest(
    input: &ReleaseSurfaceGenerateInput,
) -> Result<ReleaseSurfaceManifest, ReleaseSurfaceError> {
    require_absolute(&input.repo_root, "repo_root")?;
    require_absolute(&input.release_bundle, "release_bundle")?;
    require_absolute(&input.phase_a_bundle, "phase_a_bundle")?;
    require_absolute(&input.phase_a_install_root, "phase_a_install_root")?;
    require_absolute(&input.release_install_root, "release_install_root")?;
    require_absolute(&input.output, "output")?;
    require_non_empty(&input.generated_schemas, "generated_schemas")?;
    require_non_empty(&input.generated_plugins, "generated_plugins")?;
    require_non_empty(&input.generated_skills, "generated_skills")?;
    require_non_empty(&input.generated_hooks, "generated_hooks")?;
    require_non_empty(&input.generated_prompts, "generated_prompts")?;
    require_non_empty(
        &input.capability_cell_registries,
        "capability_cell_registries",
    )?;
    if input.expires_at_unix_seconds <= 0 {
        return Err(ReleaseSurfaceError::Invalid {
            field: "expires_at_unix_seconds",
            reason: "must be a positive Unix-seconds instant".to_owned(),
        });
    }
    InstallationEpoch {
        installation: input.installation.clone(),
        lineage_id: input.lineage_id.clone(),
        sequence: input.sequence,
    }
    .validate()
    .map_err(|error| ReleaseSurfaceError::Contract(format!("installation epoch: {error}")))?;

    let snapshot = capture_snapshot(&input.repo_root).map_err(|error| {
        ReleaseSurfaceError::Contract(format!("capture release source identity: {error}"))
    })?;
    if let Some(dirty) = snapshot.snapshot.dirty_delta_artifact_ref.clone() {
        return Err(ReleaseSurfaceError::DirtySourceTree(dirty));
    }
    let source_commit = snapshot.snapshot.selected_source_head.clone();
    if source_commit.len() != 40 || !source_commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ReleaseSurfaceError::Contract(format!(
            "captured source head is not a 40-hex commit identity: {source_commit}"
        )));
    }

    let phase_a = observe_phase_a_bundle(&input.phase_a_bundle, &input.generation)?;
    let route = route_profile_from_store_config(&phase_a.store_config)
        .map_err(|error| ReleaseSurfaceError::Contract(error.to_string()))?;

    let mut phase_a_executables = Vec::with_capacity(REQUIRED_ROLES.len());
    for (role, executable) in REQUIRED_ROLES {
        if executable {
            phase_a_executables.push(phase_a_fact(
                role,
                &input.phase_a_install_root,
                role,
                &phase_a.files,
            )?);
        }
    }
    let mut bundle_binaries = Vec::with_capacity(BUNDLE_BINARIES.len());
    for binary in BUNDLE_BINARIES {
        if binary == "eliot" {
            let bytes = read_bounded(
                &input.release_bundle.join(INSTALL_AUTHORITATIVE_CLI),
                "release payload",
                MAX_SURFACE_FILE_BYTES,
            )?;
            bundle_binaries.push(ReleaseSurfaceFileFact::bound(
                binary,
                &input.release_install_root.join(INSTALL_AUTHORITATIVE_CLI),
                Some(INSTALL_AUTHORITATIVE_CLI),
                &bytes,
            ));
        } else {
            let role = format!("{binary}.exe");
            bundle_binaries.push(phase_a_fact(
                binary,
                &input.phase_a_install_root,
                &role,
                &phase_a.files,
            )?);
        }
    }

    let mut signing_identities = Vec::with_capacity(bundle_binaries.len());
    for fact in &bundle_binaries {
        let digest = fact.sha256.as_ref().ok_or_else(|| {
            ReleaseSurfaceError::Contract(format!("bundle binary {} is unbound", fact.name))
        })?;
        let source = if fact.name == "eliot" {
            input.release_bundle.join(INSTALL_AUTHORITATIVE_CLI)
        } else {
            input.phase_a_bundle.join(format!("{}.exe", fact.name))
        };
        signing_identities.push(signing_identity_for(&source, &fact.name, digest)?);
    }

    let governance_profile = phase_a_fact(
        "eliotd-governor.json",
        &input.phase_a_install_root,
        "eliotd-governor.json",
        &phase_a.files,
    )?;
    let launch = &phase_a.store_config.runtime_launch;
    let installed = ReleaseSurfaceInstalledDigests {
        config: Some(vec![phase_a_fact(
            "generation.json",
            &input.phase_a_install_root,
            "generation.json",
            &phase_a.files,
        )?]),
        registration: Some(vec![
            governance_profile.clone(),
            phase_a_fact(
                "eliotd.json",
                &input.phase_a_install_root,
                "eliotd.json",
                &phase_a.files,
            )?,
        ]),
        cache: Some(vec![
            ReleaseSurfaceFileFact::pending(
                "authority.json",
                Path::new(launch.authority_descriptor_path.as_str()),
            ),
            ReleaseSurfaceFileFact::pending(
                "store-bootstrap.json",
                Path::new(launch.store_bootstrap_descriptor_path.as_str()),
            ),
        ]),
        bridges: Some(vec![
            phase_a_fact(
                "eliot-store-surreal.exe",
                &input.phase_a_install_root,
                "eliot-store-surreal.exe",
                &phase_a.files,
            )?,
            phase_a_fact(
                "surreal.exe",
                &input.phase_a_install_root,
                "surreal.exe",
                &phase_a.files,
            )?,
        ]),
    };

    let capability_registries = input
        .capability_cell_registries
        .iter()
        .enumerate()
        .map(|(index, relative)| {
            repo_relative_fact(input, &format!("capability_registry_{index}"), relative)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let product_proof = input
        .product_proof_receipts
        .iter()
        .enumerate()
        .map(|(index, path)| evidence_fact(&format!("product_proof_{index}"), path))
        .collect::<Result<Vec<_>, _>>()?;
    let migration_evidence = input
        .migration_evidence_snapshots
        .iter()
        .enumerate()
        .map(|(index, path)| evidence_fact(&format!("migration_evidence_{index}"), path))
        .collect::<Result<Vec<_>, _>>()?;
    let supersedes = match input.supersedes.as_ref() {
        Some(path) => Some(sha256_hex(&read_bounded(
            path,
            "supersedes",
            MAX_MANIFEST_BYTES,
        )?)),
        None => None,
    };
    let generated_at_unix_seconds = current_unix_seconds()?;
    let release_id = sha256_hex(
        format!(
            "eliot-release-surface:v1:{}:{}:{}:{}",
            source_commit,
            input.generation.as_str(),
            input.installation.as_str(),
            input.lineage_id.as_str()
        )
        .as_bytes(),
    );

    let mut manifest = ReleaseSurfaceManifest {
        wire_id: Some(MANIFEST_WIRE_ID.to_owned()),
        schema_version: Some(MANIFEST_SCHEMA_VERSION.to_owned()),
        surface_digest: None,
        release_id: Some(release_id),
        product_and_source_identity: Some(ReleaseSurfaceProductAndSourceIdentity {
            product: Some(env!("CARGO_PKG_NAME").to_owned()),
            product_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            source_commit: Some(source_commit),
            source_root: Some(snapshot.snapshot.selected_repository_root.clone()),
            source_snapshot_sha256: Some(snapshot.snapshot.snapshot_sha256.clone()),
            transaction_id: Some(input.transaction_id.clone()),
            installation: Some(input.installation.clone()),
            installation_lineage_id: Some(input.lineage_id.clone()),
            installation_sequence: Some(input.sequence),
            profile: Some(input.profile),
            generation: Some(input.generation.clone()),
        }),
        architecture_and_implementation_digests: Some(
            ReleaseSurfaceArchitectureAndImplementationDigests {
                normative_pair_ref: Some(NORMATIVE_PAIR_REF.to_owned()),
                architecture_sha256: Some(
                    snapshot.snapshot.normative_pair.architecture_sha256.clone(),
                ),
                implementation_sha256: Some(
                    snapshot
                        .snapshot
                        .normative_pair
                        .implementation_sha256
                        .clone(),
                ),
            },
        ),
        generated_schema_plugin_skill_hook_and_prompt_digests: Some(
            ReleaseSurfaceGeneratedDigests {
                schemas: Some(release_payload_facts(
                    input,
                    "generated_schema",
                    &input.generated_schemas,
                )?),
                plugins: Some(release_payload_facts(
                    input,
                    "generated_plugin",
                    &input.generated_plugins,
                )?),
                skills: Some(release_payload_facts(
                    input,
                    "generated_skill",
                    &input.generated_skills,
                )?),
                hooks: Some(release_payload_facts(
                    input,
                    "generated_hook",
                    &input.generated_hooks,
                )?),
                prompts: Some(release_payload_facts(
                    input,
                    "generated_prompt",
                    &input.generated_prompts,
                )?),
            },
        ),
        installed_cache_config_registration_and_bridge_digests: Some(installed),
        executable_package_route_and_module_generation_digests: Some(
            ReleaseSurfaceExecutablePackageRouteDigests {
                bundle_binaries: Some(bundle_binaries),
                phase_a_executables: Some(phase_a_executables),
                phase_a_package_manifest_digest: Some(phase_a.package_manifest_digest.clone()),
                phase_a_evidence_digest: Some(phase_a.evidence_digest.clone()),
                phase_a_template_content_digest: Some(phase_a.template_digest.clone()),
                route_profile: Some(route.clone()),
            },
        ),
        active_service_process_store_and_user_broker_fingerprints: Some(runtime_fingerprints(
            &route, &phase_a,
        )),
        capability_and_governance_profile_refs: Some(ReleaseSurfaceCapabilityAndGovernanceRefs {
            governance_profile: Some(governance_profile),
            capability_cell_registries: Some(capability_registries),
        }),
        migration_and_rollback_refs: Some(ReleaseSurfaceMigrationAndRollbackRefs {
            rollback_command: Some(input.recovery_command.clone()),
            supersedes_manifest_sha256: supersedes,
            prior_generation: input.prior_generation.clone(),
            migration_evidence_snapshots: Some(migration_evidence),
            product_proof_receipts: Some(product_proof),
        }),
        invalidation_and_expiry: Some(ReleaseSurfaceInvalidationAndExpiry {
            generated_at_unix_seconds: Some(generated_at_unix_seconds),
            expires_at_unix_seconds: Some(input.expires_at_unix_seconds),
            invalidated_by: Some(vec![
                "accepted bytes differ from the manifest content digest".to_owned(),
                "the expiry instant elapsed".to_owned(),
                "bound migration evidence belongs to another source head".to_owned(),
                "the installed route profile names another generation".to_owned(),
            ]),
        }),
        release_receipt_and_signing_identity: Some(ReleaseSurfaceReceiptAndSigningIdentity {
            release_receipt: release_receipt_fact(input, "RELEASE.json", RELEASE_RECEIPT, true)?,
            staged_payload_manifest: release_receipt_fact(
                input,
                "STAGED_PAYLOAD_MANIFEST.json",
                STAGED_PAYLOAD_MANIFEST,
                true,
            )?,
            signing_evidence: release_receipt_fact(
                input,
                "SIGNING_VERIFIED.json",
                SIGNING_EVIDENCE,
                false,
            )?,
            signing_identities: Some(signing_identities),
        }),
    };
    manifest.surface_digest = Some(manifest.compute_surface_digest()?);
    Ok(manifest)
}

macro_rules! compare_optional_fields {
    ($collector:expr, $section:expr, $expected:expr, $observed:expr, $render:expr, [$($field:ident),+ $(,)?]) => {
        $(
            optional_field(
                $collector,
                $section,
                stringify!($field),
                $expected.$field.as_ref(),
                $observed.$field.as_ref(),
                $render,
            );
        )+
    };
}

fn optional_field<T, F>(
    collector: &mut DriftCollector,
    section: ReleaseSurfaceSection,
    field: &str,
    expected: Option<&T>,
    observed: Option<&T>,
    render: F,
) where
    T: PartialEq,
    F: Fn(&T) -> String,
{
    match (expected, observed) {
        (None, _) => collector.missing(
            section,
            field,
            None,
            "the required manifest field is absent",
        ),
        (Some(_), None) => collector.missing(
            section,
            field,
            expected.map(render),
            "the observed field is absent from the installed surface",
        ),
        (Some(expected), Some(observed)) => {
            collector.scalar(section, field, &render(expected), &render(observed));
        }
    }
}

fn render_text(value: &String) -> String {
    value.clone()
}

fn render_number(value: &u64) -> String {
    value.to_string()
}

fn render_list(value: &Vec<String>) -> String {
    joined_list(value)
}

#[derive(Default)]
struct DriftCollector {
    findings: Vec<ReleaseSurfaceFinding>,
}

impl DriftCollector {
    fn push(
        &mut self,
        section: ReleaseSurfaceSection,
        field: &str,
        verdict: ReleaseSurfaceFieldVerdict,
        expected: Option<String>,
        observed: Option<String>,
        detail: &str,
    ) {
        self.findings.push(ReleaseSurfaceFinding {
            section,
            field: field.to_owned(),
            verdict,
            expected,
            observed,
            detail: detail.to_owned(),
        });
    }

    fn scalar(
        &mut self,
        section: ReleaseSurfaceSection,
        field: &str,
        expected: &str,
        observed: &str,
    ) {
        let verdict = if expected == observed {
            ReleaseSurfaceFieldVerdict::Match
        } else {
            ReleaseSurfaceFieldVerdict::Mismatch
        };
        let detail = if verdict == ReleaseSurfaceFieldVerdict::Match {
            "the observed identity equals the accepted manifest identity"
        } else {
            "the observed identity diverges from the accepted manifest identity"
        };
        self.push(
            section,
            field,
            verdict,
            Some(expected.to_owned()),
            Some(observed.to_owned()),
            detail,
        );
    }

    fn missing(
        &mut self,
        section: ReleaseSurfaceSection,
        field: &str,
        expected: Option<String>,
        detail: &str,
    ) {
        self.push(
            section,
            field,
            ReleaseSurfaceFieldVerdict::Missing,
            expected,
            None,
            detail,
        );
    }

    fn unknown(&mut self, section: ReleaseSurfaceSection, field: &str, detail: &str) {
        self.push(
            section,
            field,
            ReleaseSurfaceFieldVerdict::Unknown,
            None,
            None,
            detail,
        );
    }

    fn stale(
        &mut self,
        section: ReleaseSurfaceSection,
        field: &str,
        expected: Option<String>,
        observed: Option<String>,
        detail: &str,
    ) {
        self.push(
            section,
            field,
            ReleaseSurfaceFieldVerdict::Stale,
            expected,
            observed,
            detail,
        );
    }

    /// A required manifest field that this front door cannot observe on its
    /// own: absent is `MISSING`, present without an independent port is
    /// `UNKNOWN` and is never upgraded to a match.
    fn declared_only(
        &mut self,
        section: ReleaseSurfaceSection,
        field: &str,
        declared: bool,
        cross_check: &str,
    ) {
        if declared {
            self.unknown(
                section,
                field,
                &format!(
                    "bound by the accepted manifest; this read-only front door has no independent \
                     observation port, and the cross-check is {cross_check}"
                ),
            );
        } else {
            self.missing(
                section,
                field,
                None,
                "the required manifest field is absent",
            );
        }
    }

    fn file(&mut self, section: ReleaseSurfaceSection, field: &str, fact: &ReleaseSurfaceFileFact) {
        if matches!(
            fact.materialization,
            ReleaseSurfaceMaterialization::PendingPhaseB
        ) {
            self.unknown(
                section,
                field,
                &format!(
                    "the release bound the pending Phase-B descriptor {}; this front door has no \
                     observation port for it",
                    fact.installed_path
                ),
            );
            return;
        }
        let Some(expected) = fact.sha256.clone() else {
            self.missing(
                section,
                field,
                Some(fact.installed_path.clone()),
                "a bound artifact must carry its exact release digest",
            );
            return;
        };
        match observed_file_digest(Path::new(&fact.installed_path)) {
            Ok(None) => self.missing(
                section,
                field,
                Some(expected),
                "the installed artifact named by the manifest is absent",
            ),
            Ok(Some((size, digest))) => {
                if digest == expected && size == fact.size {
                    self.scalar(section, field, &expected, &digest);
                } else {
                    self.push(
                        section,
                        field,
                        ReleaseSurfaceFieldVerdict::Mismatch,
                        Some(expected),
                        Some(digest),
                        "the installed artifact bytes differ from the accepted release bytes",
                    );
                }
            }
            Err(error) => self.unknown(
                section,
                field,
                &format!("the installed artifact could not be read: {error}"),
            ),
        }
    }

    fn facts(
        &mut self,
        section: ReleaseSurfaceSection,
        field: &str,
        facts: Option<&Vec<ReleaseSurfaceFileFact>>,
    ) {
        match facts {
            None => self.missing(
                section,
                field,
                None,
                "the required manifest field is absent",
            ),
            Some(facts) if facts.is_empty() => self.missing(
                section,
                field,
                None,
                "the manifest binds no artifact of a required kind",
            ),
            Some(facts) => {
                for (index, fact) in facts.iter().enumerate() {
                    self.file(section, &format!("{field}[{index}]"), fact);
                }
            }
        }
    }
}

fn compare_route_profile(
    collector: &mut DriftCollector,
    expected: Option<&ReleaseSurfaceRouteProfile>,
    observed: &ObservedRoute,
) {
    let section = ReleaseSurfaceSection::ExecutablePackageRouteAndModuleGenerationDigests;
    let Some(expected) = expected else {
        collector.missing(
            section,
            "route_profile",
            None,
            "the required route profile is absent from the manifest",
        );
        return;
    };
    let observed = match observed {
        ObservedRoute::Projected(route) => route.as_ref(),
        ObservedRoute::Divergent(reason) => {
            collector.push(
                section,
                "route_profile",
                ReleaseSurfaceFieldVerdict::Mismatch,
                expected.generation.clone(),
                None,
                reason,
            );
            return;
        }
        ObservedRoute::Unavailable => {
            collector.unknown(
                section,
                "route_profile",
                "the accepted manifest declares no installed Store configuration path, so the \
                 route profile has no observation port in this comparison",
            );
            return;
        }
    };
    compare_optional_fields!(
        collector,
        section,
        expected,
        observed,
        render_text,
        [
            profile,
            portable_root,
            installation,
            installation_lineage_id,
            generation,
            authority_state_fence,
            authority_descriptor_path,
            authority_descriptor_digest,
            supervision_authority_state,
            supervision_lease_scope_id,
            runtime_state_roots_digest,
            installation_root,
            host_state_root,
            store_data_root,
            kernel_work_root,
            kernel_artifact_digest,
            host_artifact_digest,
            watchdog_artifact_digest,
            doctor_artifact_digest,
            testd_artifact_digest,
            native_worker_artifact_digest,
            wasm_host_artifact_digest,
            eliotd_artifact_digest,
            store_bridge_artifact_digest,
            canonical_store_artifact_digest,
            eliotd_config_digest,
            eliotd_descriptor_digest,
            eliotd_launch_nonce,
            protected_snapshot_digest,
            runtime_launch_digest,
            store_config_digest,
            store_config_path,
            store_credential_target,
            store_schema_generation,
            live_store_bind,
            live_store_endpoint,
            live_store_namespace,
            live_store_database,
        ]
    );
    compare_optional_fields!(
        collector,
        section,
        expected,
        observed,
        render_number,
        [installation_sequence, authority_generation]
    );
    compare_optional_fields!(
        collector,
        section,
        expected,
        observed,
        render_list,
        [
            kernel_arguments,
            store_bridge_arguments,
            canonical_store_arguments
        ]
    );
}

fn compare_migration_evidence(collector: &mut DriftCollector, manifest: &ReleaseSurfaceManifest) {
    let section = ReleaseSurfaceSection::MigrationAndRollbackRefs;
    let evidence = manifest
        .migration_and_rollback_refs
        .as_ref()
        .and_then(|refs| refs.migration_evidence_snapshots.as_ref());
    collector.facts(section, "migration_evidence_snapshots", evidence);
    let Some(expected_commit) = manifest
        .product_and_source_identity
        .as_ref()
        .and_then(|identity| identity.source_commit.clone())
    else {
        return;
    };
    let Some(pair) = manifest.architecture_and_implementation_digests.as_ref() else {
        return;
    };
    let facts: &[ReleaseSurfaceFileFact] = match evidence {
        Some(facts) => facts.as_slice(),
        None => &[],
    };
    for (index, fact) in facts.iter().enumerate() {
        let field = format!("migration_evidence_snapshots[{index}]");
        let Ok(bytes) = fs::read(&fact.installed_path) else {
            continue;
        };
        let Ok(artifact) = serde_json::from_slice::<SnapshotExecutionArtifact>(&bytes) else {
            collector.push(
                section,
                &field,
                ReleaseSurfaceFieldVerdict::Mismatch,
                Some(expected_commit.clone()),
                None,
                "the bound migration evidence is not a current-system evidence snapshot",
            );
            continue;
        };
        if artifact.validate().is_err() {
            collector.push(
                section,
                &field,
                ReleaseSurfaceFieldVerdict::Mismatch,
                Some(expected_commit.clone()),
                Some(artifact.snapshot.selected_source_head.clone()),
                "the bound migration evidence does not satisfy its own receipt binding",
            );
            continue;
        }
        let observed_head = artifact.snapshot.selected_source_head.clone();
        if observed_head == expected_commit {
            collector.scalar(
                section,
                &field,
                &expected_commit,
                &artifact.snapshot.selected_source_head,
            );
        } else {
            collector.stale(
                section,
                &field,
                Some(expected_commit.clone()),
                Some(observed_head),
                "the bound migration evidence belongs to another source head, so this manifest no \
                 longer describes the installed surface",
            );
        }
        optional_field(
            collector,
            section,
            &format!("{field}.architecture_sha256"),
            pair.architecture_sha256.as_ref(),
            Some(&artifact.snapshot.normative_pair.architecture_sha256),
            render_text,
        );
        optional_field(
            collector,
            section,
            &format!("{field}.implementation_sha256"),
            pair.implementation_sha256.as_ref(),
            Some(&artifact.snapshot.normative_pair.implementation_sha256),
            render_text,
        );
    }
}

fn compare_release_identity(collector: &mut DriftCollector, manifest: &ReleaseSurfaceManifest) {
    let section = ReleaseSurfaceSection::ProductAndSourceIdentity;
    let Some(identity) = manifest.product_and_source_identity.as_ref() else {
        return;
    };
    optional_field(
        collector,
        section,
        "product",
        identity.product.as_ref(),
        Some(&env!("CARGO_PKG_NAME").to_owned()),
        render_text,
    );
    optional_field(
        collector,
        section,
        "product_version",
        identity.product_version.as_ref(),
        Some(&env!("CARGO_PKG_VERSION").to_owned()),
        render_text,
    );
    let cross_check = "the bound release-scoped migration evidence snapshots";
    for (field, present) in [
        ("source_commit", identity.source_commit.is_some()),
        ("source_root", identity.source_root.is_some()),
        (
            "source_snapshot_sha256",
            identity.source_snapshot_sha256.is_some(),
        ),
        ("transaction_id", identity.transaction_id.is_some()),
        ("installation", identity.installation.is_some()),
        (
            "installation_lineage_id",
            identity.installation_lineage_id.is_some(),
        ),
        (
            "installation_sequence",
            identity.installation_sequence.is_some(),
        ),
        ("profile", identity.profile.is_some()),
        ("generation", identity.generation.is_some()),
    ] {
        collector.declared_only(section, field, present, cross_check);
    }
    let pair_section = ReleaseSurfaceSection::ArchitectureAndImplementationDigests;
    if let Some(pair) = manifest.architecture_and_implementation_digests.as_ref() {
        for (field, present) in [
            ("normative_pair_ref", pair.normative_pair_ref.is_some()),
            ("architecture_sha256", pair.architecture_sha256.is_some()),
            (
                "implementation_sha256",
                pair.implementation_sha256.is_some(),
            ),
        ] {
            collector.declared_only(pair_section, field, present, cross_check);
        }
    }
}

fn compare_generated_surfaces(collector: &mut DriftCollector, manifest: &ReleaseSurfaceManifest) {
    let section = ReleaseSurfaceSection::GeneratedSchemaPluginSkillHookAndPromptDigests;
    if let Some(generated) = manifest
        .generated_schema_plugin_skill_hook_and_prompt_digests
        .as_ref()
    {
        collector.facts(section, "schemas", generated.schemas.as_ref());
        collector.facts(section, "plugins", generated.plugins.as_ref());
        collector.facts(section, "skills", generated.skills.as_ref());
        collector.facts(section, "hooks", generated.hooks.as_ref());
        collector.facts(section, "prompts", generated.prompts.as_ref());
    }
}

fn compare_installed_surface(collector: &mut DriftCollector, manifest: &ReleaseSurfaceManifest) {
    let section = ReleaseSurfaceSection::InstalledCacheConfigRegistrationAndBridgeDigests;
    if let Some(installed) = manifest
        .installed_cache_config_registration_and_bridge_digests
        .as_ref()
    {
        collector.facts(section, "config", installed.config.as_ref());
        collector.facts(section, "registration", installed.registration.as_ref());
        collector.facts(section, "cache", installed.cache.as_ref());
        collector.facts(section, "bridges", installed.bridges.as_ref());
    }
}

fn compare_executables_and_route(
    collector: &mut DriftCollector,
    manifest: &ReleaseSurfaceManifest,
    observed_route: &ObservedRoute,
) {
    let section = ReleaseSurfaceSection::ExecutablePackageRouteAndModuleGenerationDigests;
    if let Some(executable) = manifest
        .executable_package_route_and_module_generation_digests
        .as_ref()
    {
        collector.facts(
            section,
            "bundle_binaries",
            executable.bundle_binaries.as_ref(),
        );
        collector.facts(
            section,
            "phase_a_executables",
            executable.phase_a_executables.as_ref(),
        );
        let cross_check =
            "the exact per-binary installed digests and the re-read route profile of this section";
        collector.declared_only(
            section,
            "phase_a_package_manifest_digest",
            executable.phase_a_package_manifest_digest.is_some(),
            cross_check,
        );
        collector.declared_only(
            section,
            "phase_a_evidence_digest",
            executable.phase_a_evidence_digest.is_some(),
            cross_check,
        );
        collector.declared_only(
            section,
            "phase_a_template_content_digest",
            executable.phase_a_template_content_digest.is_some(),
            cross_check,
        );
    }
    compare_route_profile(
        collector,
        manifest
            .executable_package_route_and_module_generation_digests
            .as_ref()
            .and_then(|value| value.route_profile.as_ref()),
        observed_route,
    );
}

fn compare_runtime_fingerprints(
    collector: &mut DriftCollector,
    manifest: &ReleaseSurfaceManifest,
    observed_route: &ObservedRoute,
) {
    let section = ReleaseSurfaceSection::ActiveServiceProcessStoreAndUserBrokerFingerprints;
    let Some(runtime) = manifest
        .active_service_process_store_and_user_broker_fingerprints
        .as_ref()
    else {
        return;
    };
    let observed = observed_route.projected();
    optional_field(
        collector,
        section,
        "active_runtime_generation",
        runtime.active_runtime_generation.as_ref(),
        observed.and_then(|route| route.generation.as_ref()),
        render_text,
    );
    optional_field(
        collector,
        section,
        "authority_generation",
        runtime.authority_generation.as_ref(),
        observed.and_then(|route| route.authority_generation.as_ref()),
        render_number,
    );
    optional_field(
        collector,
        section,
        "supervision_lease_scope_id",
        runtime.supervision_lease_scope_id.as_ref(),
        observed.and_then(|route| route.supervision_lease_scope_id.as_ref()),
        render_text,
    );
    optional_field(
        collector,
        section,
        "runtime_state_roots_digest",
        runtime.runtime_state_roots_digest.as_ref(),
        observed.and_then(|route| route.runtime_state_roots_digest.as_ref()),
        render_text,
    );
    optional_field(
        collector,
        section,
        "live_store_identity",
        runtime.live_store_identity.as_ref(),
        observed.map(live_store_identity_text).as_ref(),
        render_text,
    );
    optional_field(
        collector,
        section,
        "store_credential_target",
        runtime.store_credential_target.as_ref(),
        observed.and_then(|route| route.store_credential_target.as_ref()),
        render_text,
    );
    optional_field(
        collector,
        section,
        "protected_snapshot_digest",
        runtime.protected_snapshot_digest.as_ref(),
        observed.and_then(|route| route.protected_snapshot_digest.as_ref()),
        render_text,
    );
    collector.declared_only(
        section,
        "user_broker_notify_artifact_digest",
        runtime.user_broker_notify_artifact_digest.is_some(),
        "the per-user Notify adapter digest compared in \
         installed_cache_config_registration_and_bridge_digests",
    );
    let liveness = runtime
        .process_liveness
        .clone()
        .unwrap_or_else(|| "UNOBSERVED".to_owned());
    collector.unknown(
        section,
        "process_liveness",
        &format!(
            "service and process liveness have no observation port in this read-only comparison; \
             the release recorded {liveness}"
        ),
    );
}

fn compare_capability_and_governance(
    collector: &mut DriftCollector,
    manifest: &ReleaseSurfaceManifest,
) {
    let section = ReleaseSurfaceSection::CapabilityAndGovernanceProfileRefs;
    let Some(capability) = manifest.capability_and_governance_profile_refs.as_ref() else {
        return;
    };
    match capability.governance_profile.as_ref() {
        None => collector.missing(
            section,
            "governance_profile",
            None,
            "the release binds no governance profile descriptor",
        ),
        Some(fact) => collector.file(section, "governance_profile", fact),
    }
    collector.facts(
        section,
        "capability_cell_registries",
        capability.capability_cell_registries.as_ref(),
    );
}

fn compare_migration_and_rollback(
    collector: &mut DriftCollector,
    manifest: &ReleaseSurfaceManifest,
) {
    let section = ReleaseSurfaceSection::MigrationAndRollbackRefs;
    collector.facts(
        section,
        "product_proof_receipts",
        manifest
            .migration_and_rollback_refs
            .as_ref()
            .and_then(|refs| refs.product_proof_receipts.as_ref()),
    );
    if let Some(refs) = manifest.migration_and_rollback_refs.as_ref() {
        let cross_check = "the retained installation transaction store";
        collector.declared_only(
            section,
            "rollback_command",
            refs.rollback_command.is_some(),
            cross_check,
        );
        collector.declared_only(
            section,
            "supersedes_manifest_sha256",
            refs.supersedes_manifest_sha256.is_some(),
            "the superseded release manifest retained beside this one",
        );
        collector.declared_only(
            section,
            "prior_generation",
            refs.prior_generation.is_some(),
            "the prior generation retained by the installation registry",
        );
    }
    compare_migration_evidence(collector, manifest);
}

fn compare_release_receipt(collector: &mut DriftCollector, manifest: &ReleaseSurfaceManifest) {
    let section = ReleaseSurfaceSection::ReleaseReceiptAndSigningIdentity;
    let Some(receipt) = manifest.release_receipt_and_signing_identity.as_ref() else {
        return;
    };
    match receipt.release_receipt.as_ref() {
        None => collector.missing(
            section,
            "release_receipt",
            None,
            "the release binds no release receipt",
        ),
        Some(fact) => collector.file(section, "release_receipt", fact),
    }
    match receipt.staged_payload_manifest.as_ref() {
        None => collector.missing(
            section,
            "staged_payload_manifest",
            None,
            "the release binds no staged payload manifest",
        ),
        Some(fact) => collector.file(section, "staged_payload_manifest", fact),
    }
    match receipt.signing_evidence.as_ref() {
        None => collector.unknown(
            section,
            "signing_evidence",
            "an unsigned or unfinalized release publishes no signing evidence; its absence is \
             recorded, not granted",
        ),
        Some(fact) => collector.file(section, "signing_evidence", fact),
    }
    match receipt.signing_identities.as_ref() {
        None => collector.missing(
            section,
            "signing_identities",
            None,
            "the release binds no Authenticode signing identity",
        ),
        Some(identities) if identities.is_empty() => collector.missing(
            section,
            "signing_identities",
            None,
            "the release binds an empty Authenticode signing identity set",
        ),
        Some(identities) => {
            for (index, identity) in identities.iter().enumerate() {
                let field = format!("signing_identities[{index}]");
                if identity.verdict.is_empty() {
                    collector.missing(
                        section,
                        &field,
                        None,
                        "the signing identity carries no WinTrust verdict",
                    );
                } else {
                    collector.scalar(section, &field, "Valid", &identity.verdict);
                }
            }
        }
    }
}

fn compare_invalidation(
    collector: &mut DriftCollector,
    manifest: &ReleaseSurfaceManifest,
    observed_at_unix_seconds: i64,
) {
    let section = ReleaseSurfaceSection::InvalidationAndExpiry;
    let Some(invalidation) = manifest.invalidation_and_expiry.as_ref() else {
        return;
    };
    collector.declared_only(
        section,
        "generated_at_unix_seconds",
        invalidation.generated_at_unix_seconds.is_some(),
        "the manifest creation instant recorded by the release step",
    );
    match invalidation.expires_at_unix_seconds {
        None => collector.missing(
            section,
            "expires_at_unix_seconds",
            None,
            "the required manifest field is absent",
        ),
        Some(expiry) => {
            if observed_at_unix_seconds > expiry {
                collector.stale(
                    section,
                    "expires_at_unix_seconds",
                    Some(expiry.to_string()),
                    Some(observed_at_unix_seconds.to_string()),
                    "the accepted manifest no longer describes its release after expiry",
                );
            } else {
                collector.push(
                    section,
                    "expires_at_unix_seconds",
                    ReleaseSurfaceFieldVerdict::Match,
                    Some(expiry.to_string()),
                    Some(observed_at_unix_seconds.to_string()),
                    "the accepted manifest has not passed its expiry instant",
                );
            }
        }
    }
    collector.declared_only(
        section,
        "invalidated_by",
        invalidation
            .invalidated_by
            .as_ref()
            .is_some_and(|values| !values.is_empty()),
        "the exact drift verdicts this comparison emits",
    );
}

/// Current wall-clock instant used for expiry comparison, in Unix seconds.
pub fn observed_unix_seconds() -> Result<i64, ReleaseSurfaceError> {
    current_unix_seconds()
}

/// Generate and publish exactly one immutable manifest for one installable
/// release.
///
/// The returned bytes are the exact published byte set. No later code path in
/// this binary reopens the destination for writing.
pub fn generate_release_surface_manifest(
    input: &ReleaseSurfaceGenerateInput,
) -> Result<(ReleaseSurfaceManifest, Vec<u8>), ReleaseSurfaceError> {
    let manifest = build_manifest(input)?;
    let bytes = publish_manifest(&manifest, &input.output)?;
    Ok((manifest, bytes))
}

fn publish_manifest(
    manifest: &ReleaseSurfaceManifest,
    output: &Path,
) -> Result<Vec<u8>, ReleaseSurfaceError> {
    require_absolute(output, "output")?;
    if fs::symlink_metadata(output).is_ok() {
        return Err(ReleaseSurfaceError::ManifestExists(output.to_owned()));
    }
    let mut bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|error| ReleaseSurfaceError::Serialization(error.to_string()))?;
    bytes.push(b'\n');
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH);
    }
    let mut file = options
        .open(output)
        .map_err(|error| ReleaseSurfaceError::Io {
            path: output.display().to_string(),
            detail: error.to_string(),
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| ReleaseSurfaceError::Io {
            path: output.display().to_string(),
            detail: error.to_string(),
        })?;
    drop(file);
    let mut permissions = fs::metadata(output)
        .map_err(|error| ReleaseSurfaceError::Io {
            path: output.display().to_string(),
            detail: error.to_string(),
        })?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(output, permissions).map_err(|error| ReleaseSurfaceError::Io {
        path: output.display().to_string(),
        detail: error.to_string(),
    })?;
    let readback = read_bounded(output, "output", MAX_MANIFEST_BYTES)?;
    if readback != bytes {
        return Err(ReleaseSurfaceError::ManifestReadback(
            output.display().to_string(),
        ));
    }
    Ok(bytes)
}

/// Compare one accepted manifest against the observed installation.
///
/// The comparison is read-only: it reads the manifest before and after the
/// comparison, records both digests, and never regenerates, repairs, or
/// re-signs the accepted bytes.
pub fn verify_release_surface(
    manifest_path: &Path,
    observed_at_unix_seconds: i64,
) -> Result<ReleaseSurfaceDriftReport, ReleaseSurfaceError> {
    require_absolute(manifest_path, "manifest")?;
    let before = read_bounded(manifest_path, "manifest", MAX_MANIFEST_BYTES)?;
    let manifest: ReleaseSurfaceManifest = serde_json::from_slice(&before)
        .map_err(|error| ReleaseSurfaceError::Serialization(error.to_string()))?;
    let recomputed = manifest.compute_surface_digest()?;
    let self_digest_verified = manifest.surface_digest.as_deref() == Some(recomputed.as_str());
    let observed_route = observed_route_profile(&manifest);

    let mut collector = DriftCollector::default();
    let identity_section = ReleaseSurfaceSection::ProductAndSourceIdentity;
    match manifest.wire_id.as_deref() {
        Some(MANIFEST_WIRE_ID) => collector.scalar(
            identity_section,
            "wire_id",
            MANIFEST_WIRE_ID,
            MANIFEST_WIRE_ID,
        ),
        other => collector.push(
            identity_section,
            "wire_id",
            ReleaseSurfaceFieldVerdict::Mismatch,
            Some(MANIFEST_WIRE_ID.to_owned()),
            other.map(str::to_owned),
            "the accepted file is not a release-surface manifest",
        ),
    }
    match manifest.schema_version.as_deref() {
        Some(MANIFEST_SCHEMA_VERSION) => collector.scalar(
            identity_section,
            "schema_version",
            MANIFEST_SCHEMA_VERSION,
            MANIFEST_SCHEMA_VERSION,
        ),
        other => collector.push(
            identity_section,
            "schema_version",
            ReleaseSurfaceFieldVerdict::Mismatch,
            Some(MANIFEST_SCHEMA_VERSION.to_owned()),
            other.map(str::to_owned),
            "the accepted manifest schema version is not the current one",
        ),
    }
    let digest_section = ReleaseSurfaceSection::InvalidationAndExpiry;
    if self_digest_verified {
        collector.scalar(digest_section, "surface_digest", &recomputed, &recomputed);
    } else {
        collector.push(
            digest_section,
            "surface_digest",
            ReleaseSurfaceFieldVerdict::Mismatch,
            Some(recomputed.clone()),
            manifest.surface_digest.clone(),
            "the accepted manifest bytes do not reproduce their own content digest",
        );
    }
    for section in REQUIRED_SECTIONS {
        let field = "section_present";
        if manifest.carries(section) {
            collector.scalar(section, field, "BOUND", "BOUND");
        } else {
            collector.missing(
                section,
                field,
                None,
                "the required I19.8 section is absent from the accepted manifest",
            );
        }
    }

    compare_release_identity(&mut collector, &manifest);
    compare_generated_surfaces(&mut collector, &manifest);
    compare_installed_surface(&mut collector, &manifest);
    compare_executables_and_route(&mut collector, &manifest, &observed_route);
    compare_runtime_fingerprints(&mut collector, &manifest, &observed_route);
    compare_capability_and_governance(&mut collector, &manifest);
    compare_migration_and_rollback(&mut collector, &manifest);
    compare_release_receipt(&mut collector, &manifest);
    compare_invalidation(&mut collector, &manifest, observed_at_unix_seconds);

    let after = read_bounded(manifest_path, "manifest", MAX_MANIFEST_BYTES)?;
    let findings = collector.into_sorted_findings();
    let mut counts = ReleaseSurfaceVerdictCounts::default();
    for finding in &findings {
        match finding.verdict {
            ReleaseSurfaceFieldVerdict::Match => counts.matched += 1,
            ReleaseSurfaceFieldVerdict::Missing => counts.missing += 1,
            ReleaseSurfaceFieldVerdict::Mismatch => counts.mismatched += 1,
            ReleaseSurfaceFieldVerdict::Stale => counts.stale += 1,
            ReleaseSurfaceFieldVerdict::Unknown => counts.unknown += 1,
        }
    }
    let drift = findings.iter().any(|finding| finding.verdict.is_drift());
    let sections_present = REQUIRED_SECTIONS
        .into_iter()
        .filter(|section| manifest.carries(*section))
        .collect();
    Ok(ReleaseSurfaceDriftReport {
        contract: DRIFT_REPORT_CONTRACT.to_owned(),
        contract_version: DRIFT_REPORT_CONTRACT_VERSION.to_owned(),
        manifest_path: manifest_path.display().to_string(),
        manifest_sha256_before: sha256_hex(&before),
        manifest_sha256_after: sha256_hex(&after),
        manifest_bytes_unchanged: before == after,
        manifest_self_digest_verified: self_digest_verified,
        surface_digest: recomputed,
        release_id: manifest.release_id.clone(),
        generation: manifest
            .product_and_source_identity
            .as_ref()
            .and_then(|identity| identity.generation.as_ref())
            .map(|value| value.as_str().to_owned()),
        sections_present,
        counts,
        findings,
        disposition: if drift {
            ReleaseSurfaceDisposition::Drift
        } else {
            ReleaseSurfaceDisposition::Verified
        },
        manifest_mutated: false,
        observed_at_unix_seconds,
    })
}

impl DriftCollector {
    fn into_sorted_findings(mut self) -> Vec<ReleaseSurfaceFinding> {
        self.findings.sort_by(|left, right| {
            (left.section.as_str(), &left.field).cmp(&(right.section.as_str(), &right.field))
        });
        self.findings
    }
}
