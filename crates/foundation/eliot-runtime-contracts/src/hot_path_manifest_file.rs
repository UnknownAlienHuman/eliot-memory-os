//! Loader for the checked-in I12.14 hot-path declaration file (issue #1734).
//!
//! #1733 landed `bins/eliot-kernel/hot-path.toml` and `bins/eliotd/hot-path.toml`
//! as the two service-local declaration sources, and this module is the one
//! place their bytes become a validated [`HotPathManifestSetV1`]. Both
//! composition roots load their own declaration through it, so a boundary hook
//! binds to the *declared* operation identity, queue bounds and degradation
//! rather than to a string the hook itself spells.
//!
//! # Why the file shape is its own type
//!
//! The contract's [`ContractVersion`] is a structured `{major, minor, patch}`
//! on the wire, and it stays that way: this module does not weaken it. A
//! declaration *file* is a configuration artifact that spells a version as the
//! exact `major.minor.patch` text, so the file shape is its own type with its own
//! three field-by-field converters. A file that spells a version the contract
//! does not admit fails closed at the parse, and every other field is read
//! straight into the contract type, so a declaration file can declare no shape
//! the contract does not have.
//!
//! Loading a declaration gives the hooks their bounded vocabulary. It admits no
//! work, starts no process and proves no measurement: every value the hooks emit
//! is still an observation.

use std::path::{Path, PathBuf};

use eliot_contracts::ContractVersion;
use serde::{Deserialize, Serialize};

use crate::RuntimeContractError;
use crate::hot_path::{
    HOT_PATH_MANIFEST_VERSION, HotPathDegradation, HotPathExternalCall, HotPathManifest,
    HotPathManifestSetV1, HotPathProfileRef, HotPathQueueBounds, HotPathQueueDeclaration,
    HotPathSnapshotDependency, HotPathUnsupportedOperation,
};

/// Exact schema tag the checked-in declaration files carry.
pub const HOT_PATH_MANIFEST_SCHEMA: &str = "eliot.foundation.runtime-contracts.hot-path.v1";

/// File name of a service-local I12.14 declaration, relative to its crate root.
pub const HOT_PATH_MANIFEST_FILE_NAME: &str = "hot-path.toml";

/// One supported operation exactly as a declaration file spells it.
///
/// Every field converts into its contract counterpart field for field, so an
/// omitted or misspelled row is a parse failure rather than a defaulted
/// declaration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportedOperationFile {
    operation: String,
    operation_version: String,
    owning_service: String,
    entrypoint: String,
    crate_closure: Vec<String>,
    immutable_snapshot_dependencies: Vec<HotPathSnapshotDependency>,
    queues_and_capacity: Vec<HotPathQueueDeclaration>,
    synchronous_external_calls: Vec<HotPathExternalCall>,
    fallback_or_degradation: DegradationFile,
    hot_path_profile_ref: HotPathProfileRef,
}

impl SupportedOperationFile {
    /// Converts this file row into the contract's declaration shape.
    fn into_manifest(self) -> Result<HotPathManifest, HotPathManifestFileError> {
        Ok(HotPathManifest {
            operation: self.operation,
            operation_version: parse_contract_version(&self.operation_version)?,
            owning_service: self.owning_service,
            entrypoint: self.entrypoint,
            crate_closure: self.crate_closure,
            immutable_snapshot_dependencies: self.immutable_snapshot_dependencies,
            queues_and_capacity: self.queues_and_capacity,
            synchronous_external_calls: self.synchronous_external_calls,
            fallback_or_degradation: self.fallback_or_degradation.into_contract(),
            hot_path_profile_ref: self.hot_path_profile_ref,
        })
    }
}

/// The bounded degradation a declaration file spells.
///
/// I12.14 names exactly four bounded results — a durable handle, an unknown, an
/// owner probe, or a recovery directive — and this type is the file's own
/// spelling of that closed set. A file that names a result outside the four
/// fails closed at the parse rather than defaulting to `Unknown`, so a
/// declaration can never widen or silently narrow the bounded vocabulary the
/// contract froze.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum DegradationFile {
    /// The exact durable handle for work that is still pending.
    Handle {
        /// Reference to the retained handle.
        handle_ref: String,
    },
    /// The current position is unknown and is reported as such.
    Unknown {},
    /// The exact probe result the blocking owner produced.
    Probe {
        /// Reference to the owner's probe result.
        probe_ref: String,
    },
    /// The typed recovery directive of the blocking owner.
    RecoveryDirective {
        /// Reference to the owner's recovery directive.
        directive_ref: String,
    },
}

impl DegradationFile {
    /// Converts the file's spelling into the contract's frozen degradation.
    fn into_contract(self) -> HotPathDegradation {
        match self {
            Self::Handle { handle_ref } => HotPathDegradation::Handle { handle_ref },
            Self::Unknown {} => HotPathDegradation::Unknown,
            Self::Probe { probe_ref } => HotPathDegradation::Probe { probe_ref },
            Self::RecoveryDirective { directive_ref } => {
                HotPathDegradation::RecoveryDirective { directive_ref }
            }
        }
    }
}

/// The on-disk shape of one service-local declaration file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HotPathManifestFile {
    schema: String,
    contract_version: String,
    owning_service: String,
    supported_operations: Vec<SupportedOperationFile>,
    unsupported_operations: Vec<HotPathUnsupportedOperation>,
}

/// One admitted service-local declaration and the identity of the bytes it came
/// from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedHotPathManifest {
    /// The validated declaration set.
    pub set: HotPathManifestSetV1,
    /// SHA-256 of the exact declaration bytes, so a readback can name the
    /// declaration a record was measured under.
    pub manifest_file_digest: String,
    /// Exact path the declaration was read from.
    pub source_path: PathBuf,
}

impl AdmittedHotPathManifest {
    /// The declaration for exactly one operation this set declares.
    ///
    /// An operation the set does not declare is an error rather than a default,
    /// so a hook can never measure a boundary against a declaration that does
    /// not describe it.
    ///
    /// # Errors
    ///
    /// Returns [`HotPathOperationDeclarationError`] when the set declares no
    /// such operation or declares it more than once.
    pub fn operation(
        &self,
        operation: &str,
    ) -> Result<&HotPathManifest, HotPathOperationDeclarationError> {
        let mut found = self
            .set
            .supported_operations
            .iter()
            .filter(|manifest| manifest.operation == operation);
        let first = found
            .next()
            .ok_or(HotPathOperationDeclarationError::OperationNotDeclared {
                operation: operation.to_owned(),
                owning_service: self.set.owning_service.clone(),
            })?;
        if found.next().is_some() {
            return Err(HotPathOperationDeclarationError::OperationDeclaredTwice {
                operation: operation.to_owned(),
            });
        }
        Ok(first)
    }

    /// The declared in-flight item bound of exactly one queue of one operation.
    ///
    /// # Errors
    ///
    /// Returns [`HotPathOperationDeclarationError::QueueNotDeclared`] when the
    /// operation declares no such queue.
    pub fn queue_bounds(
        &self,
        operation: &str,
        queue_id: &str,
    ) -> Result<HotPathQueueBounds, HotPathOperationDeclarationError> {
        let manifest = self.operation(operation)?;
        manifest
            .queues_and_capacity
            .iter()
            .find(|queue| queue.queue_id == queue_id)
            .map(|queue| queue.bounds)
            .ok_or_else(|| HotPathOperationDeclarationError::QueueNotDeclared {
                operation: operation.to_owned(),
                queue_id: queue_id.to_owned(),
            })
    }
}

/// A declared operation or queue this set does not contain, or contains twice.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HotPathOperationDeclarationError {
    /// The set declares no such operation.
    #[error("hot-path declaration for '{operation}' does not exist in service '{owning_service}'")]
    OperationNotDeclared {
        /// The operation identity that was looked up.
        operation: String,
        /// The service whose declaration set was consulted.
        owning_service: String,
    },
    /// The set declares the operation more than once, so no single
    /// authoritative declaration exists for it.
    #[error("hot-path declaration for '{operation}' is declared more than once")]
    OperationDeclaredTwice {
        /// The operation identity that was looked up.
        operation: String,
    },
    /// The declared operation does not contain the named queue.
    #[error("hot-path operation '{operation}' declares no queue '{queue_id}'")]
    QueueNotDeclared {
        /// The operation identity that was consulted.
        operation: String,
        /// The queue identity that was looked up.
        queue_id: String,
    },
}

/// Returns the declaration path a service-local manifest lives at.
///
/// # Errors
///
/// Returns [`RuntimeContractError::Blank`] when the crate root is blank.
pub fn hot_path_manifest_path(crate_root: &Path) -> Result<PathBuf, RuntimeContractError> {
    if crate_root.as_os_str().is_empty() {
        return Err(RuntimeContractError::Blank {
            field: "crate_root",
        });
    }
    Ok(crate_root.join(HOT_PATH_MANIFEST_FILE_NAME))
}

/// Admits one service-local declaration file's exact bytes.
///
/// The admitted value is a validated [`HotPathManifestSetV1`] plus the digest of
/// the bytes it came from. A file that names the wrong schema, an unsupported
/// wire revision, or a row the contract rejects is refused closed, so a boundary
/// hook can never bind to a declaration the contract does not accept.
///
/// # Errors
///
/// Returns [`HotPathManifestFileError`] when the bytes are empty, are not
/// UTF-8, do not parse, name the wrong schema or wire revision, declare an
/// operation under a foreign owning service, or declare a row the contract
/// rejects.
pub fn admit_hot_path_manifest(
    source_path: &Path,
    manifest_bytes: &[u8],
) -> Result<AdmittedHotPathManifest, HotPathManifestFileError> {
    if manifest_bytes.is_empty() {
        return Err(HotPathManifestFileError::Malformed {
            reason: "the declaration bytes are empty".to_owned(),
        });
    }
    let text = std::str::from_utf8(manifest_bytes).map_err(|error| {
        HotPathManifestFileError::Malformed {
            reason: format!("the declaration bytes are not UTF-8: {error}"),
        }
    })?;
    let file: HotPathManifestFile =
        toml::from_str(text).map_err(|error| HotPathManifestFileError::Malformed {
            reason: error.to_string(),
        })?;
    if file.schema != HOT_PATH_MANIFEST_SCHEMA {
        return Err(HotPathManifestFileError::Malformed {
            reason: format!(
                "the declaration schema is '{}' but the admitted schema is '{HOT_PATH_MANIFEST_SCHEMA}'",
                file.schema
            ),
        });
    }
    let version = parse_contract_version(&file.contract_version)?;
    if version != HOT_PATH_MANIFEST_VERSION {
        return Err(HotPathManifestFileError::UnsupportedSchemaVersion {
            found: file.contract_version,
            supported: HOT_PATH_MANIFEST_VERSION.to_string(),
        });
    }
    let owning_service = file.owning_service;
    let mut supported_operations = Vec::with_capacity(file.supported_operations.len());
    for row in file.supported_operations {
        if row.owning_service != owning_service {
            return Err(HotPathManifestFileError::Malformed {
                reason: format!(
                    "operation '{}' claims owning service '{}' inside a set owned by '{owning_service}'",
                    row.operation, row.owning_service
                ),
            });
        }
        supported_operations.push(row.into_manifest()?);
    }
    let set = HotPathManifestSetV1 {
        contract_version: version,
        owning_service,
        supported_operations,
        unsupported_operations: file.unsupported_operations,
    };
    set.validate()
        .map_err(|error| HotPathManifestFileError::Contract(error.to_string()))?;
    Ok(AdmittedHotPathManifest {
        set,
        manifest_file_digest: eliot_contracts::sha256_hex(manifest_bytes),
        source_path: source_path.to_path_buf(),
    })
}

/// A service-local declaration file that is not admissible.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HotPathManifestFileError {
    /// The bytes are empty, are not UTF-8, do not parse, or declare a row the
    /// contract rejects.
    #[error("hot-path declaration file is malformed: {reason}")]
    Malformed {
        /// Why the declaration is not admissible.
        reason: String,
    },
    /// The declared wire revision is not the one this build admits.
    #[error("hot-path declaration schema version {found} is not the admitted version {supported}")]
    UnsupportedSchemaVersion {
        /// The version the file declared.
        found: String,
        /// The version this build admits.
        supported: String,
    },
    /// A field the contract itself rejected.
    #[error("hot-path declaration file is not contract-valid: {0}")]
    Contract(String),
}

/// Parses one exact `major.minor.patch` wire revision.
///
/// The three components must all be present and decimal, so a partial or padded
/// spelling fails closed rather than defaulting a component to zero.
fn parse_contract_version(value: &str) -> Result<ContractVersion, HotPathManifestFileError> {
    let malformed = || HotPathManifestFileError::Malformed {
        reason: format!("the wire revision '{value}' is not an exact major.minor.patch version"),
    };
    let mut components = value.split('.');
    let major = components.next().ok_or_else(malformed)?;
    let minor = components.next().ok_or_else(malformed)?;
    let patch = components.next().ok_or_else(malformed)?;
    if components.next().is_some() {
        return Err(malformed());
    }
    Ok(ContractVersion::new(
        major.parse::<u16>().map_err(|_| malformed())?,
        minor.parse::<u16>().map_err(|_| malformed())?,
        patch.parse::<u16>().map_err(|_| malformed())?,
    ))
}
