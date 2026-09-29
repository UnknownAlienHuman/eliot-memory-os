//! Immutable runtime `module.toml` bytes, admitted against the accepted
//! artifact identity.
//!
//! `I14.14` places `module.toml` beside the immutable artifact under
//! `modules/<module_id>/<semver>/<artifact_hash>/`, and `I6.4` requires every
//! hot module to ship that file. This module owns the admission of those exact
//! bytes:
//!
//! * the manifest is loaded from the admitted artifact location only, never
//!   from an ambient working directory or a mutable source-tree copy, and its
//!   file name is qualified by the module identity because the release bundle
//!   stages every admitted runtime artifact into one flat directory;
//! * the file-byte digest (SHA-256 over the retained bytes) and the canonical
//!   parsed-contract digest are two distinct identities and are both retained;
//! * the artifact hash is taken from the accepted build identity, so a manifest
//!   never certifies its own bytes and no self-hash is circular;
//! * a missing, duplicate, unknown or unsupported field rejects without a
//!   permissive default, because the manifest types carry
//!   `serde(deny_unknown_fields)` and every I6.4 field is mandatory;
//! * a digest alone authenticates nothing here: it binds bytes to a declared
//!   contract and never grants the declared effects.
//!
//! Admission is a pure check over retained bytes. It performs no I/O, admits no
//! process, and manufactures no readiness, health or activation authority.

use std::path::{Path, PathBuf};

use eliot_contracts::{ArtifactId, ContractId, ContractVersion, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ModuleContract, RuntimeContractError};

/// File stem of the runtime module manifest placed beside the artifact.
///
/// The stem is qualified by the module identity because the release bundle
/// stages every admitted runtime artifact flat into one `runtime/` directory.
/// A single fixed file name there would let one module's manifest be read as
/// another's, so the manifest beside an artifact is named for the module it
/// declares. The file is still loaded from the admitted artifact location; the
/// name only keeps two artifacts that share one directory from sharing one
/// manifest.
pub const MODULE_MANIFEST_FILE_STEM: &str = "module";

/// Returns the manifest file name that belongs beside one module's artifact.
///
/// The name is a pure function of the module identity, so the same module
/// always resolves the same file and two modules staged into one directory
/// never resolve each other's manifest.
pub fn module_manifest_file_name(module_id: &ContractId) -> String {
    format!("{MODULE_MANIFEST_FILE_STEM}.{}.toml", module_id.as_str())
}

/// The only manifest schema version this loader admits.
///
/// A newer manifest revision is a new artifact revision, never a field the
/// loader fills in by default.
pub const MODULE_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// The protected `module.toml` document: a versioned envelope around the one
/// shared [`ModuleContract`].
///
/// The envelope is what makes the schema versioned without forking the shared
/// contract. Both the envelope and the contract refuse unknown fields, so a
/// manifest that carries an unrecognised protected field is rejected instead of
/// being silently ignored.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleManifest {
    /// Schema revision of this manifest document.
    pub schema_version: u32,
    /// The complete I6.4 contract shipped beside the artifact.
    pub contract: ModuleContract,
}

/// The identities retained when a manifest's exact bytes are admitted.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedModuleManifest {
    /// Module the admitted manifest declares.
    pub module_id: ContractId,
    /// Contract version the admitted manifest declares.
    pub version: ContractVersion,
    /// Artifact identity the admitted manifest is bound to.
    pub artifact_id: ArtifactId,
    /// File-byte identity: SHA-256 over the exact retained manifest bytes.
    pub manifest_digest: String,
    /// Canonical parsed-contract identity, distinct from the file-byte digest.
    pub contract_digest: String,
    /// Schema revision of the admitted manifest document.
    pub schema_version: u32,
    /// The contract parsed from those exact bytes.
    pub contract: ModuleContract,
}

/// Resolves the manifest path beside an admitted artifact for one module.
///
/// The artifact location is supplied by the caller from the accepted
/// installation/launch identity. A relative or absent parent is refused: the
/// manifest is never resolved against the process working directory, and a
/// source-tree copy of the manifest is not an admitted artifact location.
///
/// The resolved name is qualified by `module_id` because the release bundle
/// stages every admitted runtime artifact flat into one directory. Without that
/// qualification every artifact in that directory would resolve the same file,
/// so the first module to load would answer for all of them. The module
/// identity is the caller's own declaration of which artifact it is, not a
/// value read out of the bytes being loaded.
pub fn admitted_manifest_path(
    artifact_path: &Path,
    module_id: &ContractId,
) -> Result<PathBuf, RuntimeContractError> {
    if !artifact_path.is_absolute() {
        return Err(RuntimeContractError::InvalidField {
            field: "artifact_path",
            reason: "the admitted artifact location must be an absolute path",
        });
    }
    let directory = artifact_path
        .parent()
        .ok_or(RuntimeContractError::InvalidField {
            field: "artifact_path",
            reason: "the admitted artifact location has no parent directory",
        })?;
    Ok(directory.join(module_manifest_file_name(module_id)))
}

/// Admits the exact retained manifest bytes against the accepted artifact
/// identity.
///
/// The returned value carries both the file-byte digest and the canonical
/// parsed-contract digest. The artifact identity is supplied by the accepted
/// build identity, never read out of the manifest, so a manifest cannot certify
/// its own artifact.
pub fn admit_module_manifest(
    accepted_artifact: &ArtifactId,
    manifest_bytes: &[u8],
) -> Result<AdmittedModuleManifest, RuntimeContractError> {
    if manifest_bytes.is_empty() {
        return Err(RuntimeContractError::MalformedModuleManifest {
            reason: "the retained manifest bytes are empty".to_owned(),
        });
    }
    let text = std::str::from_utf8(manifest_bytes).map_err(|error| {
        RuntimeContractError::MalformedModuleManifest {
            reason: format!("the manifest bytes are not UTF-8: {error}"),
        }
    })?;
    let manifest: ModuleManifest =
        toml::from_str(text).map_err(|error| RuntimeContractError::MalformedModuleManifest {
            reason: error.to_string(),
        })?;
    if manifest.schema_version != MODULE_MANIFEST_SCHEMA_VERSION {
        return Err(RuntimeContractError::UnsupportedManifestSchemaVersion {
            found: manifest.schema_version,
            supported: MODULE_MANIFEST_SCHEMA_VERSION,
        });
    }
    manifest.contract.validate()?;
    if &manifest.contract.artifact_id != accepted_artifact {
        return Err(RuntimeContractError::ManifestArtifactMismatch {
            declared: manifest.contract.artifact_id.to_string(),
            accepted: accepted_artifact.to_string(),
        });
    }

    let canonical = canonical_json_bytes(&manifest.contract).map_err(|error| {
        RuntimeContractError::MalformedModuleManifest {
            reason: format!("the contract is not canonically serialisable: {error}"),
        }
    })?;
    Ok(AdmittedModuleManifest {
        module_id: manifest.contract.module_id.clone(),
        version: manifest.contract.version,
        artifact_id: manifest.contract.artifact_id.clone(),
        manifest_digest: sha256_hex(manifest_bytes),
        contract_digest: sha256_hex(&canonical),
        schema_version: manifest.schema_version,
        contract: manifest.contract,
    })
}

/// Compares the contract published in a handshake projection to the contract
/// parsed from the admitted manifest bytes.
///
/// A digest alone is not a substitute for this comparison: the published value
/// is compared field-by-field with the contract that those exact bytes carry,
/// so a substituted or edited projection is refused.
pub fn compare_published_projection(
    admitted: &AdmittedModuleManifest,
    published: &ModuleContract,
) -> Result<(), RuntimeContractError> {
    if &admitted.contract == published {
        return Ok(());
    }
    let published_digest = sha256_hex(&canonical_json_bytes(published).map_err(|error| {
        RuntimeContractError::MalformedModuleManifest {
            reason: format!("the published contract is not canonically serialisable: {error}"),
        }
    })?);
    Err(RuntimeContractError::PublishedProjectionMismatch {
        module: admitted.module_id.to_string(),
        admitted: admitted.contract_digest.clone(),
        published: published_digest,
    })
}
