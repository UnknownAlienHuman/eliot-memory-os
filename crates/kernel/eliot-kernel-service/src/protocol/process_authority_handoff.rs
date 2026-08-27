//! Architecture micro-module for process-authority handoff (Implementation P-03/P-04).
//! Descriptor is not authority and owns no I/O, state, effect, Store, or process launch.

use std::collections::BTreeSet;

use eliot_contracts::{ResourceGeneration, StateFence, sha256_hex};
use eliot_kernel_core::AuthoritySnapshotBindingWire;
use eliot_platform::{PlatformHandle, SecretReference};
use eliot_runtime_contracts::ProvisionedSupervisionAuthority;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::KernelServiceError;

use super::handle;

/// Versioned, secret-free one-shot process-authority handoff.
///
/// This record contains only identities, bindings, policy references and a
/// Credential Manager locator. It is not authority and cannot be used without
/// the matching secret and durable ORS snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct ProcessAuthorityHandoffDescriptor {
    pub contract_version: u16,
    pub handoff_id: PlatformHandle,
    pub handoff_nonce: PlatformHandle,
    pub authority_id: eliot_process::DispatchAuthorityId,
    pub snapshot_binding: AuthoritySnapshotBindingWire,
    pub state_fence: StateFence,
    pub generation: ResourceGeneration,
    pub revision_policy_binding: PlatformHandle,
    pub dispatch_key: SecretReference,
    /// Installer-provisioned public supervision authority. The reference is
    /// Kernel-root-relative and contains no signing bytes.
    pub supervision_authority: ProvisionedSupervisionAuthority,
    pub descriptor_sha256: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub contour_refs: Vec<PlatformHandle>,
}

impl ProcessAuthorityHandoffDescriptor {
    /// Current descriptor schema revision.
    pub const CONTRACT_VERSION: u16 = 3;
    /// Maximum number of contour references admitted in one handoff.
    pub const MAX_CONTOUR_REFS: usize = 32;

    /// Returns the canonical secret-free bytes covered by `descriptor_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, KernelServiceError> {
        let mut unsigned = self.clone();
        unsigned.descriptor_sha256.clear();
        serde_json::to_vec(&unsigned).map_err(|_| KernelServiceError::InvalidField {
            field: "descriptor_sha256",
            reason: "cannot canonicalize descriptor",
        })
    }

    /// Computes the descriptor digest through the one canonical procedure.
    pub fn compute_digest(&self) -> Result<String, KernelServiceError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Returns a descriptor with its checked canonical digest populated.
    pub fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.descriptor_sha256 = self.compute_digest()?;
        Ok(self)
    }

    /// Verifies the explicit descriptor digest without performing other checks.
    pub fn verify_digest(&self) -> Result<(), KernelServiceError> {
        if self.descriptor_sha256.len() != 64
            || !self
                .descriptor_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(KernelServiceError::InvalidField {
                field: "descriptor_sha256",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        if self.compute_digest()? != self.descriptor_sha256 {
            return Err(KernelServiceError::InvalidField {
                field: "descriptor_sha256",
                reason: "descriptor digest mismatch",
            });
        }
        Ok(())
    }

    /// Validates syntax, digest material, and exact fence bindings without
    /// applying the one-shot admission expiry.
    ///
    /// Recovery must be able to inspect an immutable descriptor after its
    /// admission interval has elapsed.  The durable ORS handoff and exact
    /// replay snapshot decide whether that is a permitted restart; callers
    /// admitting a fresh Reserved handoff must additionally require
    /// `expires_at_ms > now_ms`.
    pub fn validate_structure(&self) -> Result<(), KernelServiceError> {
        if self.contract_version != Self::CONTRACT_VERSION {
            return Err(KernelServiceError::InvalidField {
                field: "contract_version",
                reason: "unsupported version",
            });
        }
        for (value, field) in [
            (&self.handoff_id, "handoff_id"),
            (&self.handoff_nonce, "handoff_nonce"),
            (&self.revision_policy_binding, "revision_policy_binding"),
        ] {
            handle(value, field)?;
        }
        if self.contour_refs.is_empty() {
            return Err(KernelServiceError::InvalidField {
                field: "contour_refs",
                reason: "must not be empty",
            });
        }
        if self.contour_refs.len() > Self::MAX_CONTOUR_REFS {
            return Err(KernelServiceError::InvalidField {
                field: "contour_refs",
                reason: "exceeds the bounded contour reference limit",
            });
        }
        let mut unique_refs = BTreeSet::new();
        for value in &self.contour_refs {
            handle(value, "contour_refs")?;
            if !unique_refs.insert(value.as_str()) {
                return Err(KernelServiceError::InvalidField {
                    field: "contour_refs",
                    reason: "references must be unique",
                });
            }
        }
        if self.issued_at_ms < 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(KernelServiceError::InvalidField {
                field: "expires_at_ms",
                reason: "descriptor has invalid bounds",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| KernelServiceError::HandshakeMismatch {
                field: "state_fence",
            })?;
        let exact_epoch = self.state_fence.authority_epoch.value();
        let exact_state_fence =
            eliot_ors::StateFenceSnapshot::capture(&self.state_fence, exact_epoch).map_err(
                |_| KernelServiceError::HandshakeMismatch {
                    field: "state_fence",
                },
            )?;
        if self.state_fence.resource_generation != self.generation
            || self.snapshot_binding.authority_id != self.authority_id
            || self.snapshot_binding.authority_epoch.current.epoch != exact_epoch
            || self.snapshot_binding.state_fence != exact_state_fence
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "authority_binding",
            });
        }
        if self.dispatch_key.provider.as_str() != "windows-credential-manager" {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "dispatch_key.provider",
            });
        }
        handle(&self.dispatch_key.key, "dispatch_key.key")?;
        self.supervision_authority
            .validate()
            .map_err(|_| KernelServiceError::InvalidField {
                field: "supervision_authority",
                reason: "invalid installer-provisioned supervision authority",
            })?;
        if self.supervision_authority.authority_generation != self.generation {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "supervision_authority.authority_generation",
            });
        }
        if self.descriptor_sha256.len() != 64
            || !self
                .descriptor_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(KernelServiceError::InvalidField {
                field: "descriptor_sha256",
                reason: "must be a SHA-256 digest",
            });
        }
        AuthoritySnapshotBindingWire::validate(&self.snapshot_binding)?;
        self.verify_digest()
    }

    /// Validates syntax, digest material, time bounds, and exact fence
    /// bindings for a fresh one-shot admission.
    pub fn validate(&self, now_ms: i64) -> Result<(), KernelServiceError> {
        self.validate_structure()?;
        if self.expires_at_ms <= now_ms {
            return Err(KernelServiceError::InvalidField {
                field: "expires_at_ms",
                reason: "descriptor is expired",
            });
        }
        Ok(())
    }
}
