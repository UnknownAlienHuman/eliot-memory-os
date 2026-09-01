//! Kernel build-time contract types and their exact fail-closed errors.
//!
//! Traceability: Architecture A13.2, A13.5, ARCH-AUTH-01, ARCH-SEC-02,
//! ARCH-RES-01; Implementation I1.11, I14.16, P.3, and I2.23.
//!
//! This module retains typed composition inputs, protected receipt bindings,
//! and pre-service-loop errors. It does not mint authority, hide Host binding,
//! own semantic state, or introduce an alternate failure domain. The existing
//! public types are re-exported by the crate root without changing their API.

use std::fmt;
use std::path::{Path, PathBuf};

use super::{AuthorityHandoffRecord, KernelDispatchKey, is_lower_sha256};
use eliot_kernel_service::ProcessAuthorityHandoffDescriptor;
use eliot_platform::PortError;
#[cfg(windows)]
use eliot_runtime_contracts::ProvisionedSupervisionAuthority;

/// Host-approved protected key reference and installation-pinned public trust
/// anchor for Kernel-owned supervision leases.
///
/// The reference identifies a service-SID-bound DPAPI-NG ciphertext below the
/// approved Kernel work root; it never carries the signing seed.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionLeaseAuthorityConfig {
    pub authority: ProvisionedSupervisionAuthority,
}

/// Host-injected, manifest-bound roots and generation identity for the
/// Kernel-owned eliotd live receipt.  The absolute paths are not authority on
/// their own: the full `RuntimeStateRoots` digest and active manifest identities
/// are mandatory members of the same launch binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EliotdReceiptRootBinding {
    receipt_root: PathBuf,
    kernel_ors_root: PathBuf,
    runtime_state_roots_digest: String,
    installation_id: String,
    approved_generation: String,
}

impl EliotdReceiptRootBinding {
    /// Constructs the complete manifest-derived publication binding.
    pub fn new(
        receipt_root: impl Into<PathBuf>,
        kernel_ors_root: impl Into<PathBuf>,
        runtime_state_roots_digest: impl Into<String>,
        installation_id: impl Into<String>,
        approved_generation: impl Into<String>,
    ) -> Result<Self, String> {
        let binding = Self {
            receipt_root: receipt_root.into(),
            kernel_ors_root: kernel_ors_root.into(),
            runtime_state_roots_digest: runtime_state_roots_digest.into(),
            installation_id: installation_id.into(),
            approved_generation: approved_generation.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        for (name, path) in [
            ("receipt_root", &self.receipt_root),
            ("kernel_ors_root", &self.kernel_ors_root),
        ] {
            if !path.is_absolute()
                || path.as_os_str().is_empty()
                || path.to_string_lossy().chars().any(char::is_control)
            {
                return Err(format!(
                    "eliotd {name} must be an absolute control-free path"
                ));
            }
        }
        if !is_lower_sha256(&self.runtime_state_roots_digest) {
            return Err("RuntimeStateRoots digest must be lowercase SHA-256".to_owned());
        }
        for (name, value) in [
            ("installation identity", &self.installation_id),
            ("approved generation", &self.approved_generation),
        ] {
            if value.trim().is_empty()
                || value != value.trim()
                || value.chars().any(char::is_control)
            {
                return Err(format!("eliotd {name} is empty or contains control"));
            }
        }
        Ok(())
    }

    /// Returns the manifest-selected Host state root.
    pub fn receipt_root(&self) -> &Path {
        &self.receipt_root
    }

    /// Returns the manifest-selected Kernel ORS root.
    pub fn kernel_ors_root(&self) -> &Path {
        &self.kernel_ors_root
    }

    /// Returns the installer-owned `RuntimeStateRoots` digest.
    pub fn runtime_state_roots_digest(&self) -> &str {
        &self.runtime_state_roots_digest
    }

    /// Returns the active installation identity.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Returns the active manifest generation identity.
    pub fn approved_generation(&self) -> &str {
        &self.approved_generation
    }
}

#[cfg(windows)]
impl SupervisionLeaseAuthorityConfig {
    /// Validates the installer receipt before any ciphertext file is opened.
    pub fn validate(&self) -> Result<(), String> {
        self.authority.validate().map_err(|error| error.to_string())
    }
}

/// Errors raised before the Kernel is admitted to its service loop.
#[derive(Debug)]
pub enum KernelBuildError {
    /// The platform adapter rejected the `WorkScope` root.
    Platform(PortError),
    /// The selected transport is not valid.
    Transport(eliot_ipc::TransportError),
    /// The bounded runtime rejected its fixed production policy.
    Runtime(eliot_runtime::ConfigError),
    /// The durable ORS store could not be opened.
    Ors(String),
    /// The generation route could not be initialized.
    Core(String),
    /// The Kernel lifecycle gateway could not be initialized.
    Service(String),
    /// Host has not injected an approved canonical-store bootstrap binding.
    StoreBootstrapRequired,
    /// This composition already owns its one canonical-store client/gateway.
    StoreAlreadyConnected,
    /// The platform could not bind the authenticated local front door.
    Principal(String),
}

/// Exact protected contour selected for one authority descriptor read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityDescriptorContour {
    /// Current-user portable contour rooted at an existing user-owned directory.
    PortableCurrentUser { root: PathBuf },
    /// Installation-wide protected `ProgramData` contour.
    ProgramData,
}

/// Typed fail-closed result for protected authority preparation.
#[derive(Debug, Eq, PartialEq)]
pub enum AuthorityPreparationError {
    /// The descriptor path could not be retained and read in the selected contour.
    ProtectedInput,
    /// The independent expected digest was malformed or did not match the bytes.
    DigestMismatch,
    /// The descriptor failed its closed contract validation.
    DescriptorInvalid,
    /// The descriptor is absent from ORS and outside its fresh admission
    /// interval at the reservation linearization point.
    DescriptorNotFresh,
    /// Credential Manager did not return an acceptable secret.
    CredentialUnavailable,
    /// The credential was not exactly one non-zero 32-byte dispatch key.
    CredentialInvalid,
    /// The durable one-shot handoff was already reserved, consumed, or unknown.
    Replay,
    /// Durable handoff persistence did not establish a known outcome.
    PersistenceUnknown,
}

impl fmt::Display for AuthorityPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProtectedInput => "protected authority input unavailable",
            Self::DigestMismatch => "authority descriptor digest mismatch",
            Self::DescriptorInvalid => "authority descriptor is invalid",
            Self::DescriptorNotFresh => "authority descriptor is not fresh for admission",
            Self::CredentialUnavailable => "authority credential unavailable",
            Self::CredentialInvalid => "authority credential is invalid",
            Self::Replay => "authority handoff replay or recovery is required",
            Self::PersistenceUnknown => "authority handoff persistence outcome is unknown",
        })
    }
}

impl std::error::Error for AuthorityPreparationError {}

#[allow(dead_code)]
pub(crate) struct PreparedAuthorityMaterial {
    pub(crate) descriptor: ProcessAuthorityHandoffDescriptor,
    pub(crate) key: KernelDispatchKey,
    /// The durable Reserved/Consumed handoff identity that gates this
    /// controller.  Reserved is the activation intent committed by ORS;
    /// it must never be replaced by an in-memory marker.
    pub(crate) handoff: AuthorityHandoffRecord,
}

impl fmt::Display for KernelBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(f, "platform composition failed: {error}"),
            Self::Transport(error) => write!(f, "IPC composition failed: {error}"),
            Self::Runtime(error) => write!(f, "runtime composition failed: {error:?}"),
            Self::Ors(error) => write!(f, "ORS composition failed: {error}"),
            Self::Core(error) => write!(f, "Kernel decision composition failed: {error}"),
            Self::Service(error) => write!(f, "Kernel service composition failed: {error}"),
            Self::StoreBootstrapRequired => {
                write!(f, "Host-approved canonical-store bootstrap is required")
            }
            Self::StoreAlreadyConnected => {
                write!(f, "canonical-store client/gateway is already connected")
            }
            Self::Principal(error) => write!(f, "principal composition failed: {error}"),
        }
    }
}

impl std::error::Error for KernelBuildError {}
