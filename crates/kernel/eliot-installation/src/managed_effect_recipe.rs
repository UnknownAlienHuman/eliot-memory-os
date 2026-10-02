//! Signed, closed effect recipes for the managed portable-tool path.
//!
//! This module is a declarative edge from an accepted catalogue row into the
//! existing installation transaction owner. It does not run a process or
//! mutate the host. A recipe binds the exact source directory identity, exact
//! manifest and file digests, the one installation-selected `managed-tools`
//! destination, a closed action/effect mapping, and exact readback
//! postconditions. Request text, family labels and `managed_surfaces` never
//! supply an effect.

use std::path::{Path, PathBuf};

use eliot_platform_windows::{FileIdentity, PackageManifest, validate_package_relative_path};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    InstallationError, ManagedEnvironmentAction, PackageArtifactDigest, PlatformHandle,
    WindowsPathIdentity, handle, is_lower_sha256,
};

/// The only portable managed-package recipe adapter currently admitted.
pub const PORTABLE_PACKAGE_RECIPE_ID: &str = "portable-package-v1";

/// Fixed child directory below the selected installation immutable-binaries
/// root. The signed catalogue cannot choose an absolute destination or another
/// parent chain.
pub const MANAGED_TOOLS_RELATIVE_ROOT: &str = "managed-tools";

/// Closed mapping from a request action to one effect owned by the existing
/// installation transaction.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEffectOperation {
    /// Stage an absent portable package generation and its non-launching
    /// registration.
    InstallPortableGeneration,
    /// Stage a side-by-side generation and switch only the owned registration.
    UpdatePortableGeneration,
    /// Re-stage the exact approved generation without adopting foreign files.
    RepairPortableGeneration,
    /// Remove only the exact receipt-owned generation and registration.
    RemoveOwnedPortableGeneration,
    /// Register an already observed artifact without starting it.
    RegisterObservedPortableGeneration,
    /// Stage and read back a new immutable configuration generation.
    ReconfigurePortableGeneration,
}

impl ManagedEffectOperation {
    /// The one request action this effect implements.
    #[must_use]
    pub const fn action(self) -> ManagedEnvironmentAction {
        match self {
            Self::InstallPortableGeneration => ManagedEnvironmentAction::Install,
            Self::UpdatePortableGeneration => ManagedEnvironmentAction::Update,
            Self::RepairPortableGeneration => ManagedEnvironmentAction::Repair,
            Self::RemoveOwnedPortableGeneration => ManagedEnvironmentAction::Remove,
            Self::RegisterObservedPortableGeneration => ManagedEnvironmentAction::Register,
            Self::ReconfigurePortableGeneration => ManagedEnvironmentAction::Reconfigure,
        }
    }

    const fn allowed_changes(self) -> &'static [ManagedResourceChange] {
        use ManagedResourceChange as Change;
        match self {
            Self::InstallPortableGeneration => &[Change::CreatePackageGeneration, Change::CreateRegistration],
            Self::UpdatePortableGeneration => &[Change::CreatePackageGeneration, Change::ReplaceRegistration],
            Self::RepairPortableGeneration => &[Change::RepairPackageGeneration],
            Self::RemoveOwnedPortableGeneration => &[Change::RemoveRegistration, Change::RemoveOwnedGeneration],
            Self::RegisterObservedPortableGeneration => &[Change::CreateRegistration],
            Self::ReconfigurePortableGeneration => &[Change::CreateConfigurationGeneration, Change::ReplaceRegistrationConfiguration],
        }
    }

    const fn postcondition(self) -> ManagedEffectPostcondition {
        match self {
            Self::InstallPortableGeneration => ManagedEffectPostcondition::GenerationAndRegistrationReadBack,
            Self::UpdatePortableGeneration => ManagedEffectPostcondition::GenerationAndRegistrationSwitchedReadBack,
            Self::RepairPortableGeneration => ManagedEffectPostcondition::GenerationRepairedReadBack,
            Self::RemoveOwnedPortableGeneration => ManagedEffectPostcondition::OwnedGenerationAndRegistrationAbsent,
            Self::RegisterObservedPortableGeneration => ManagedEffectPostcondition::RegistrationReadBack,
            Self::ReconfigurePortableGeneration => ManagedEffectPostcondition::ConfigurationAndRegistrationReadBack,
        }
    }
}

/// Resource mutations that the transaction adapter may perform for one
/// approved action. The array in a recipe must exactly equal the mapping for
/// its [`ManagedEffectOperation`].
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedResourceChange {
    /// Create an immutable package generation below the fixed managed-tools
    /// root.
    CreatePackageGeneration,
    /// Replace an installation-owned registration with one for the new exact
    /// package generation.
    ReplaceRegistration,
    /// Reapply package bytes only under an exact existing ownership receipt.
    RepairPackageGeneration,
    /// Remove an installation-owned registration.
    RemoveRegistration,
    /// Remove package bytes only under an exact installation-owned receipt.
    RemoveOwnedGeneration,
    /// Create an immutable configuration generation.
    CreateConfigurationGeneration,
    /// Update the registration's configuration-generation reference.
    ReplaceRegistrationConfiguration,
    /// Create a registration that points to an already-observed artifact.
    CreateRegistration,
}

/// Competencies this portable adapter explicitly refuses to perform. A signed
/// recipe may declare one so admission can report why it is unsupported; the
/// transaction writer never interprets the requirement as permission.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEffectRequirement {
    /// Downloading or network access is required.
    Network,
    /// Elevation or a privileged token is required.
    Elevation,
    /// SCM or service mutation is required.
    ServiceMutation,
    /// Credential creation or mutation is required.
    CredentialMutation,
    /// Starting or invoking a process is required.
    ProcessExecution,
    /// An active core component or protected state would be changed in place.
    ProtectedCoreMutation,
}

/// Typed readback that must be established before the transaction reports the
/// action complete. Presence or process exit status is not a postcondition.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEffectPostcondition {
    /// Exact staged package files and the exact registration both read back.
    GenerationAndRegistrationReadBack,
    /// Exact new generation and owned registration switch both read back.
    GenerationAndRegistrationSwitchedReadBack,
    /// Every expected package byte is read back under its original ownership.
    GenerationRepairedReadBack,
    /// Exact receipt-owned package and registration are both absent.
    OwnedGenerationAndRegistrationAbsent,
    /// Registration identity and all executable-relative paths read back
    /// without starting the candidate.
    RegistrationReadBack,
    /// Configuration bytes and their registration reference read back.
    ConfigurationAndRegistrationReadBack,
}

/// One exact System Owner signed source/package/effect contract.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedEffectRecipe {
    /// Stable recipe discriminator. The currently supported value is
    /// [`PORTABLE_PACKAGE_RECIPE_ID`].
    pub recipe_id: PlatformHandle,
    /// Request action this entry authorizes the transaction to attempt.
    pub action: ManagedEnvironmentAction,
    /// Closed operation implementing `action`.
    pub operation: ManagedEffectOperation,
    /// Exact absolute source bundle location retained by the signed catalogue
    /// owner. It is re-opened and its identity rechecked before staging.
    pub source_bundle: PlatformHandle,
    /// Stable identity of the exact source directory.
    pub source_bundle_identity: FileIdentity,
    /// Exact package generation/version relative to the source bundle.
    pub target_family: PlatformHandle,
    /// Exact package version. The destination generation is the validated
    /// two-component path `<family>/<version>`.
    pub package_version: PlatformHandle,
    /// Exact source package manifest.
    pub package_manifest: PackageManifest,
    /// Exact SHA-256 and size for every manifest file, with no extras.
    pub expected_files: Vec<PackageArtifactDigest>,
    /// Destination below the transaction's selected `immutable_binaries`
    /// root. This portable adapter accepts only `managed-tools`.
    pub target_relative_path: PlatformHandle,
    /// Stable registration identity written/read by the existing transaction
    /// owner. It is not a command or a family display label.
    pub registration_identity: PlatformHandle,
    /// Executable files the registration may name, relative to the package
    /// generation. Every path must name a manifest entry marked executable.
    pub executable_relative_paths: Vec<PlatformHandle>,
    /// Fixed arguments for this file-managed adapter. This adapter requires an
    /// empty vector; it never takes caller shell text or arbitrary flags.
    pub fixed_arguments: Vec<String>,
    /// Exact allowed resource delta for `action`.
    pub allowed_resource_changes: Vec<ManagedResourceChange>,
    /// The competent readback the transaction owner must establish.
    pub postcondition: ManagedEffectPostcondition,
    /// Explicit requirements this narrow adapter refuses to perform.
    pub unsupported_requirements: Vec<ManagedEffectRequirement>,
}

impl ManagedEffectRecipe {
    /// Checks the full signed wire recipe without consulting caller labels or
    /// performing an effect.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.recipe_id, "managed_effect_recipe.recipe_id")?;
        if self.recipe_id.as_str() != PORTABLE_PACKAGE_RECIPE_ID {
            return Err(invalid_recipe("recipe_id", "unsupported recipe discriminator"));
        }
        if self.action != self.operation.action() {
            return Err(invalid_recipe("operation", "must implement the exact action"));
        }
        WindowsPathIdentity::parse_root(self.source_bundle.as_str(), "managed_effect_recipe.source_bundle")?;
        if self.source_bundle_identity.volume_serial_number == 0
            || self.source_bundle_identity.file_index == 0
        {
            return Err(invalid_recipe("source_bundle_identity", "must be a non-zero file identity"));
        }
        handle(&self.target_family, "managed_effect_recipe.target_family")?;
        handle(&self.package_version, "managed_effect_recipe.package_version")?;
        if validate_package_relative_path(Path::new(self.target_family.as_str()))
            .is_err()
            || self.target_family.as_str().contains('/')
            || self.target_family.as_str().contains('\\')
            || validate_package_relative_path(Path::new(self.package_version.as_str())).is_err()
            || self.package_version.as_str().contains('/')
            || self.package_version.as_str().contains('\\')
        {
            return Err(invalid_recipe("package_version", "family and version must each be one safe path component"));
        }
        let expected_generation = format!("{}/{}", self.target_family, self.package_version);
        if expected_generation != self.package_manifest.generation {
            return Err(invalid_recipe("package_manifest.generation", "must bind the exact family and version"));
        }
        let manifest_generation = validate_package_relative_path(Path::new(&self.package_manifest.generation))
            .map_err(|error| invalid_recipe("package_manifest.generation", &error.to_string()))?;
        if manifest_generation.as_str() != self.package_manifest.generation {
            return Err(invalid_recipe("package_manifest.generation", "must be canonical"));
        }
        if self.package_manifest.files.is_empty() {
            return Err(invalid_recipe("package_manifest.files", "must be non-empty and bounded"));
        }
        let normalized_manifest = PackageManifest::new(
            &self.package_manifest.generation,
            self.package_manifest.files.clone(),
        )
        .map_err(|error| invalid_recipe("package_manifest", &error.to_string()))?;
        if normalized_manifest != self.package_manifest {
            return Err(invalid_recipe("package_manifest", "must use its canonical sorted shape"));
        }
        if self.expected_files.len() != self.package_manifest.files.len() {
            return Err(invalid_recipe("expected_files", "must exactly cover the manifest inventory"));
        }
        for (index, file) in self.package_manifest.files.iter().enumerate() {
            if self.package_manifest.files[index + 1..].iter().any(|other| {
                ordinal_path_equal(&file.relative_path, &other.relative_path)
            }) {
                return Err(invalid_recipe("package_manifest.files", "contains a duplicate path"));
            }
        }
        for (file, digest) in self
            .package_manifest
            .files
            .iter()
            .zip(&self.expected_files)
        {
            let path = validate_package_relative_path(Path::new(&file.relative_path))
                .map_err(|error| invalid_recipe("package_manifest.files", &error.to_string()))?;
            if path.as_str() != file.relative_path || file.expected_size == 0 {
                return Err(invalid_recipe("package_manifest.files", "path or size is not canonical"));
            }
            if digest.relative_path != file.relative_path
                || digest.expected_size != file.expected_size
                || !is_lower_sha256(digest.sha256.as_str())
            {
                return Err(invalid_recipe("expected_files", "ordered digest/size inventory differs from the manifest"));
            }
        }
        for (index, digest) in self.expected_files.iter().enumerate() {
            if self.expected_files[index + 1..].iter().any(|other| {
                ordinal_path_equal(&digest.relative_path, &other.relative_path)
            }) {
                return Err(invalid_recipe("expected_files", "contains a duplicate path"));
            }
        }
        if self.target_relative_path.as_str() != MANAGED_TOOLS_RELATIVE_ROOT {
            return Err(invalid_recipe("target_relative_path", "must be the fixed managed-tools child"));
        }
        handle(&self.registration_identity, "managed_effect_recipe.registration_identity")?;
        if self.executable_relative_paths.is_empty()
            || self.executable_relative_paths.len() > self.package_manifest.files.len()
        {
            return Err(invalid_recipe("executable_relative_paths", "must be non-empty and bounded"));
        }
        for (index, executable) in self.executable_relative_paths.iter().enumerate() {
            handle(executable, "managed_effect_recipe.executable_relative_paths")?;
            let path = validate_package_relative_path(Path::new(executable.as_str()))
                .map_err(|error| invalid_recipe("executable_relative_paths", &error.to_string()))?;
            if path.as_str() != executable.as_str() {
                return Err(invalid_recipe("executable_relative_paths", "path must be canonical"));
            }
            if self.executable_relative_paths[index + 1..]
                .iter()
                .any(|other| ordinal_path_equal(executable.as_str(), other.as_str()))
            {
                return Err(invalid_recipe("executable_relative_paths", "contains a duplicate path"));
            }
            if !self.package_manifest.files.iter().any(|file| {
                file.executable && ordinal_path_equal(executable.as_str(), &file.relative_path)
            }) {
                return Err(invalid_recipe("executable_relative_paths", "must name executable manifest entries"));
            }
        }
        if !self.fixed_arguments.is_empty() {
            return Err(invalid_recipe("fixed_arguments", "portable file effects accept no process arguments"));
        }
        if self.allowed_resource_changes.as_slice() != self.operation.allowed_changes() {
            return Err(invalid_recipe("allowed_resource_changes", "must exactly match the closed action mapping"));
        }
        if self.postcondition != self.operation.postcondition() {
            return Err(invalid_recipe("postcondition", "must exactly match the operation's typed readback"));
        }
        for pair in self.unsupported_requirements.windows(2) {
            if pair[0] >= pair[1] {
                return Err(invalid_recipe("unsupported_requirements", "must be sorted and distinct"));
            }
        }
        Ok(())
    }

    /// Returns the fixed destination child below an installation-owned,
    /// validated `immutable_binaries` root.
    #[must_use]
    pub fn target_root(&self, immutable_binaries: &Path) -> PathBuf {
        immutable_binaries.join(MANAGED_TOOLS_RELATIVE_ROOT)
    }

    /// Rejects recipe requirements that exceed this non-privileged,
    /// file-managed adapter's authority.
    pub fn require_supported(&self) -> Result<(), ManagedEffectRequirement> {
        if let Some(requirement) = self.unsupported_requirements.first() {
            Err(*requirement)
        } else {
            Ok(())
        }
    }
}

fn ordinal_path_equal(left: &str, right: &str) -> bool {
    eliot_platform_windows::ordinal_eq_str(left, right)
}

fn invalid_recipe(field: &str, reason: &str) -> InstallationError {
    InstallationError::InvalidField {
        field: format!("managed_effect_recipe.{field}"),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod direct_tests {
    use super::*;

    #[test]
    fn six_actions_have_closed_resource_deltas_and_readbacks() {
        let cases = [
            (
                ManagedEffectOperation::InstallPortableGeneration,
                ManagedEnvironmentAction::Install,
                &[ManagedResourceChange::CreatePackageGeneration, ManagedResourceChange::CreateRegistration][..],
                ManagedEffectPostcondition::GenerationAndRegistrationReadBack,
            ),
            (
                ManagedEffectOperation::UpdatePortableGeneration,
                ManagedEnvironmentAction::Update,
                &[ManagedResourceChange::CreatePackageGeneration, ManagedResourceChange::ReplaceRegistration][..],
                ManagedEffectPostcondition::GenerationAndRegistrationSwitchedReadBack,
            ),
            (
                ManagedEffectOperation::RepairPortableGeneration,
                ManagedEnvironmentAction::Repair,
                &[ManagedResourceChange::RepairPackageGeneration][..],
                ManagedEffectPostcondition::GenerationRepairedReadBack,
            ),
            (
                ManagedEffectOperation::RemoveOwnedPortableGeneration,
                ManagedEnvironmentAction::Remove,
                &[ManagedResourceChange::RemoveRegistration, ManagedResourceChange::RemoveOwnedGeneration][..],
                ManagedEffectPostcondition::OwnedGenerationAndRegistrationAbsent,
            ),
            (
                ManagedEffectOperation::RegisterObservedPortableGeneration,
                ManagedEnvironmentAction::Register,
                &[ManagedResourceChange::CreateRegistration][..],
                ManagedEffectPostcondition::RegistrationReadBack,
            ),
            (
                ManagedEffectOperation::ReconfigurePortableGeneration,
                ManagedEnvironmentAction::Reconfigure,
                &[ManagedResourceChange::CreateConfigurationGeneration, ManagedResourceChange::ReplaceRegistrationConfiguration][..],
                ManagedEffectPostcondition::ConfigurationAndRegistrationReadBack,
            ),
        ];
        let mut actions = Vec::with_capacity(cases.len());
        for (operation, action, changes, postcondition) in cases {
            assert_eq!(operation.action(), action);
            assert_eq!(operation.allowed_changes(), changes);
            assert_eq!(operation.postcondition(), postcondition);
            assert!(!actions.contains(&action));
            actions.push(action);
        }
        assert_eq!(actions.len(), 6);
    }
}
