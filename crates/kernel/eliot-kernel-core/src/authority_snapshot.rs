//! P-07's provider-neutral authority snapshot contract.
//!
//! This private child contains only the typed, secret-free ORS metadata
//! binding, the codec port, and the provider-held sealed-byte result. It does
//! not own dispatch, process execution, persistence, lifecycle, or transport.
//!
//! Normative anchors verified in the pinned source are `A2.2` in
//! `docs/architecture/ELIOT_ARCHITECTURE.md` (uncovered authority is forbidden
//! for state/effect changes), `A12.2` in that file (identity binds to `Session`,
//! `WorkScope`, capabilities, visibility, and `Authority Epoch`), and `I1.8` in
//! `docs/architecture/ELIOT_IMPLEMENTATION.md` (Kernel verifies authority and
//! State Fence while recovery stays within the named ownership paths).

use eliot_ors::{EpochLineage, OperationIdentity, RecoveryPayload, StateFenceSnapshot};
use eliot_platform::SecretReference;
use eliot_process::{DispatchAuthorityId, DispatchPermitReplaySnapshot};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{KernelError, KernelResult};

/// Exact ORS metadata required to bind one process-authority replay snapshot.
///
/// The authority id is retained as process-contract identity, while the epoch
/// lineage and State Fence are compared byte-for-byte with the recovered ORS
/// record before its opaque payload is handed to the codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritySnapshotBinding {
    pub(super) authority_id: DispatchAuthorityId,
    pub(super) record_id: OperationIdentity,
    pub(super) authority_epoch: EpochLineage,
    pub(super) state_fence: StateFenceSnapshot,
    pub(super) created_at_ms: i64,
    pub(super) cleanup_after_ms: Option<i64>,
}

/// Checked, secret-free transport projection of an authority snapshot binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySnapshotBindingWire {
    /// Process authority identity.
    pub authority_id: DispatchAuthorityId,
    /// ORS record identity.
    pub record_id: OperationIdentity,
    /// Exact epoch lineage.
    pub authority_epoch: EpochLineage,
    /// Exact state fence snapshot.
    pub state_fence: StateFenceSnapshot,
    /// ORS creation timestamp.
    pub created_at_ms: i64,
    /// Optional ORS cleanup timestamp.
    pub cleanup_after_ms: Option<i64>,
}

impl AuthoritySnapshotBindingWire {
    /// Revalidates every nested identity, epoch, fence, and timestamp before
    /// a wire binding is admitted to a Kernel-only authority path.
    pub fn validate(&self) -> KernelResult<()> {
        self.authority_epoch.validate()?;
        self.state_fence.validate()?;
        if self.state_fence.observed_authority_epoch != self.authority_epoch.current.epoch {
            return Err(KernelError::FenceMismatch);
        }
        if self.record_id.as_str().trim().is_empty() {
            return Err(KernelError::InvalidField {
                field: "record_id",
                reason: "must be non-blank",
            });
        }
        if self.created_at_ms < 0 {
            return Err(KernelError::InvalidField {
                field: "created_at_ms",
                reason: "must not be negative",
            });
        }
        if self
            .cleanup_after_ms
            .is_some_and(|value| value <= self.created_at_ms)
        {
            return Err(KernelError::InvalidField {
                field: "cleanup_after_ms",
                reason: "must be later than created_at_ms",
            });
        }
        Ok(())
    }
}

impl AuthoritySnapshotBinding {
    /// Creates a binding for one active authority identity and fence.
    pub fn new(
        authority_id: DispatchAuthorityId,
        record_id: OperationIdentity,
        authority_epoch: EpochLineage,
        state_fence: StateFenceSnapshot,
        created_at_ms: i64,
        cleanup_after_ms: Option<i64>,
    ) -> KernelResult<Self> {
        authority_epoch.validate()?;
        if record_id.as_str().trim().is_empty() {
            return Err(KernelError::InvalidField {
                field: "record_id",
                reason: "must be non-blank",
            });
        }
        state_fence.validate()?;
        if state_fence.observed_authority_epoch != authority_epoch.current.epoch {
            return Err(KernelError::FenceMismatch);
        }
        if cleanup_after_ms.is_some_and(|value| value <= created_at_ms) {
            return Err(KernelError::InvalidField {
                field: "cleanup_after_ms",
                reason: "must be later than created_at_ms",
            });
        }
        Ok(Self {
            authority_id,
            record_id,
            authority_epoch,
            state_fence,
            created_at_ms,
            cleanup_after_ms,
        })
    }

    /// Projects the checked binding into an inert wire value.
    #[must_use]
    pub fn to_wire(&self) -> AuthoritySnapshotBindingWire {
        AuthoritySnapshotBindingWire {
            authority_id: self.authority_id.clone(),
            record_id: self.record_id.clone(),
            authority_epoch: self.authority_epoch.clone(),
            state_fence: self.state_fence.clone(),
            created_at_ms: self.created_at_ms,
            cleanup_after_ms: self.cleanup_after_ms,
        }
    }

    /// Reconstructs a binding only after rechecking every nested invariant.
    pub fn from_wire(
        wire: AuthoritySnapshotBindingWire,
        expected_authority_id: &DispatchAuthorityId,
    ) -> KernelResult<Self> {
        wire.validate()?;
        if &wire.authority_id != expected_authority_id {
            return Err(KernelError::InvalidField {
                field: "authority_id",
                reason: "does not match expected authority",
            });
        }
        Self::new(
            wire.authority_id,
            wire.record_id,
            wire.authority_epoch,
            wire.state_fence,
            wire.created_at_ms,
            wire.cleanup_after_ms,
        )
    }

    /// Reconstructs and compares a wire binding against one exact retained
    /// binding, rejecting record, epoch, fence, or timestamp substitution.
    pub fn from_wire_exact(
        wire: AuthoritySnapshotBindingWire,
        expected: &Self,
    ) -> KernelResult<Self> {
        let observed = Self::from_wire(wire, expected.authority_id())?;
        if observed != *expected {
            return Err(KernelError::FenceMismatch);
        }
        Ok(observed)
    }

    /// Returns the exact process authority identity.
    #[must_use]
    pub fn authority_id(&self) -> &DispatchAuthorityId {
        &self.authority_id
    }

    /// Returns the exact ORS record identity used for the commit.
    #[must_use]
    pub fn record_id(&self) -> &OperationIdentity {
        &self.record_id
    }

    /// Returns the active epoch lineage.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochLineage {
        &self.authority_epoch
    }

    /// Returns the exact active State Fence snapshot.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFenceSnapshot {
        &self.state_fence
    }

    /// Returns the creation timestamp bound to the ORS record.
    #[must_use]
    pub const fn created_at_ms(&self) -> i64 {
        self.created_at_ms
    }

    /// Returns the optional cleanup deadline bound to the ORS record.
    #[must_use]
    pub const fn cleanup_after_ms(&self) -> Option<i64> {
        self.cleanup_after_ms
    }
}

/// Ciphertext and its provider-held secret reference returned by the codec.
///
/// The reference is not a key and the bytes are never interpreted by ORS.
/// Implementations are expected to bind both to the supplied authority id and
/// fence before returning this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedAuthoritySnapshot {
    key: SecretReference,
    ciphertext: Vec<u8>,
}

impl SealedAuthoritySnapshot {
    /// Creates a sealed payload result for an injected codec implementation.
    pub fn new(key: SecretReference, ciphertext: Vec<u8>) -> KernelResult<Self> {
        if ciphertext.is_empty() {
            return Err(KernelError::InvalidField {
                field: "authority_snapshot_ciphertext",
                reason: "must not be empty",
            });
        }
        Ok(Self { key, ciphertext })
    }

    pub(super) fn into_parts(self) -> (SecretReference, Vec<u8>) {
        (self.key, self.ciphertext)
    }
}

/// Object-safe P-01/platform port for authority-snapshot encryption and
/// decryption.
///
/// This trait intentionally has no default implementation: P-07 cannot fake
/// encryption truth.  The `open` input remains the opaque ORS payload, and the
/// implementation must reject an unexpected authority id, epoch, or State
/// Fence rather than returning a plausible snapshot.
pub trait DispatchSnapshotCodec: Send + Sync {
    /// Seals a replay snapshot for durable ORS storage.
    fn seal(
        &self,
        snapshot: &DispatchPermitReplaySnapshot,
        binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<SealedAuthoritySnapshot>;

    /// Resolves and decrypts one opaque ORS payload into a replay snapshot.
    fn open(
        &self,
        payload: &RecoveryPayload,
        binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<DispatchPermitReplaySnapshot>;
}
