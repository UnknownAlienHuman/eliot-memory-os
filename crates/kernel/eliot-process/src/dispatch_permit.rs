//! P-03 dispatch-permit authority cell.
//!
//! This private module owns typed Kernel permit issuance/verification, the
//! recovery capability minting seam, and in-memory replay fencing. It owns no
//! process execution, lifecycle, daemon/host/watchdog/eliotd, canonical-write,
//! filesystem, network, credential, or `SurrealDB` authority.
//!
//! Normative anchors verified in `docs/normative/ELIOT_ARCHITECTURE.md`: A2.2
//! requires explicit authority for state/effect changes, and A12.2 binds
//! principal, session, capabilities, visibility, and Authority Epoch. In
//! `docs/normative/ELIOT_IMPLEMENTATION.md`, I1.8 assigns Kernel verification
//! of identity, authority, State Fence, idempotency, ordering, and generation;
//! I6.10 limits Kernel to generic authority/fence decisions and exact
//! continuation permits.

use super::{
    ActionLeaseRef, ContractError, DispatchAuthorityId, DispatchValidationContext, FencingToken,
    Generation, ImageId, JobId, OperationId, PROCESS_CONTRACT_SCHEMA_VERSION, PermitIssuance,
    ProcessExecutionBinding, ProcessIntent, ProcessRequest, ProcessTreeId, RecoveryCapability,
    SessionId, SuspendedProcessIdentity, ValidatedDispatch, hash_serialized, validate_hex_digest,
    validate_opaque_id, validate_revision_heads, validate_stored_digest,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_REPLAY_NONCES: usize = 4096;

/// Secret Kernel key material used to authenticate dispatch permits.
///
/// Possession of an arbitrary key does not grant authority: the P-04 executor
/// validates against its Kernel-owned authority instance and active key.
pub struct KernelDispatchKey([u8; 32]);

impl KernelDispatchKey {
    /// Imports exact secret bytes obtained through the Kernel credential boundary.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self, ContractError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(ContractError::InvalidValue {
                field: "kernel_dispatch_key",
                reason: "all-zero keys are forbidden",
            });
        }
        Ok(Self(bytes))
    }
}

impl Drop for KernelDispatchKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Opaque, authenticated, one-shot Kernel dispatch authority.
///
/// It deliberately has no public field constructor, `Clone`, or `Deserialize`.
/// A caller may transport its serialized bytes, but cannot produce a permit
/// accepted by the executor's active Kernel authority without the matching key.
#[derive(Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchPermit {
    pub(super) schema_version: String,
    pub(super) authority_id: DispatchAuthorityId,
    pub(super) operation_id: OperationId,
    pub(super) process_tree_id: ProcessTreeId,
    pub(super) job_id: JobId,
    pub(super) image_id: ImageId,
    pub(super) session_id: SessionId,
    pub(super) generation: Generation,
    pub(super) action_lease_ref: ActionLeaseRef,
    pub(super) state_fence: FencingToken,
    pub(super) expected_revision_heads: BTreeMap<String, String>,
    pub(super) effect_digest: String,
    pub(super) issued_at_unix_ms: u64,
    pub(super) expires_at_unix_ms: u64,
    pub(super) one_shot_nonce: String,
    pub(super) validation_revision: Option<u64>,
    pub(super) authentication_tag: String,
    pub(super) permit_digest: String,
}

#[derive(Serialize)]
struct UnsignedPermit<'a> {
    schema_version: &'a str,
    authority_id: &'a DispatchAuthorityId,
    operation_id: &'a OperationId,
    process_tree_id: &'a ProcessTreeId,
    job_id: &'a JobId,
    image_id: &'a ImageId,
    session_id: &'a SessionId,
    generation: Generation,
    action_lease_ref: &'a ActionLeaseRef,
    state_fence: &'a FencingToken,
    expected_revision_heads: &'a BTreeMap<String, String>,
    effect_digest: &'a str,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    one_shot_nonce: &'a str,
    validation_revision: Option<u64>,
}

impl DispatchPermit {
    fn unsigned(&self) -> UnsignedPermit<'_> {
        UnsignedPermit {
            schema_version: &self.schema_version,
            authority_id: &self.authority_id,
            operation_id: &self.operation_id,
            process_tree_id: &self.process_tree_id,
            job_id: &self.job_id,
            image_id: &self.image_id,
            session_id: &self.session_id,
            generation: self.generation,
            action_lease_ref: &self.action_lease_ref,
            state_fence: &self.state_fence,
            expected_revision_heads: &self.expected_revision_heads,
            effect_digest: &self.effect_digest,
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            one_shot_nonce: &self.one_shot_nonce,
            validation_revision: self.validation_revision,
        }
    }

    pub(super) fn validate_shape(&self) -> Result<(), ContractError> {
        if self.schema_version != PROCESS_CONTRACT_SCHEMA_VERSION {
            return Err(ContractError::SchemaVersion {
                expected: PROCESS_CONTRACT_SCHEMA_VERSION,
                observed: self.schema_version.clone(),
            });
        }
        validate_revision_heads(&self.expected_revision_heads)?;
        validate_hex_digest("effect_digest", &self.effect_digest)?;
        validate_hex_digest("authentication_tag", &self.authentication_tag)?;
        validate_hex_digest("permit_digest", &self.permit_digest)?;
        if self.issued_at_unix_ms == 0 || self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(ContractError::InvalidValue {
                field: "permit_freshness",
                reason: "issue time must be non-zero and precede expiry",
            });
        }
        if self.validation_revision == Some(0) {
            return Err(ContractError::InvalidValue {
                field: "validation_revision",
                reason: "must be non-zero",
            });
        }
        if self.state_fence.generation != self.generation {
            return Err(ContractError::FenceMismatch);
        }
        let expected_digest = permit_digest(&self.unsigned(), &self.authentication_tag)?;
        validate_stored_digest("permit_digest", &self.permit_digest, expected_digest)
    }

    pub(super) fn matches_intent(&self, intent: &ProcessIntent) -> bool {
        self.operation_id == intent.operation_id
            && self.process_tree_id == intent.process_tree_id
            && self.job_id == intent.job_id
            && self.image_id == intent.image_id
            && self.session_id == intent.session_id
            && self.generation == intent.generation
            && self.effect_digest == intent.effect_digest
            && self.state_fence.generation == intent.generation
    }

    /// Returns the stable digest; all other authority material stays opaque.
    pub fn digest(&self) -> &str {
        &self.permit_digest
    }
}

/// Kernel-owned issuer/validator state for one active authority key.
///
/// P-07 owns the production instance and durable nonce journal. This pure P-03
/// model makes issue/consume ordering executable without giving P-02 any
/// authority role.
pub struct DispatchPermitAuthority {
    authority_id: DispatchAuthorityId,
    key: KernelDispatchKey,
    issued_nonces: BTreeSet<String>,
    consumed_nonces: BTreeSet<String>,
    replay_revision: u64,
}

/// Durable replay-fence state persisted by the Kernel owner, never by P-02.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchPermitReplaySnapshot {
    pub(super) authority_id: DispatchAuthorityId,
    pub(super) issued_nonces: Vec<String>,
    pub(super) consumed_nonces: Vec<String>,
    pub(super) replay_revision: u64,
}

impl DispatchPermitReplaySnapshot {
    /// Validates a durable replay snapshot before it is admitted to Kernel state.
    ///
    /// The wire representation deliberately uses vectors: deserialising directly
    /// into a set would silently discard duplicate entries before they could be
    /// rejected as corrupt replay state.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.authority_id.validate()?;
        if self.replay_revision == 0 {
            return Err(ContractError::InvalidValue {
                field: "dispatch_replay_snapshot.replay_revision",
                reason: "must be non-zero",
            });
        }
        validate_replay_nonces("issued_nonces", &self.issued_nonces)?;
        validate_replay_nonces("consumed_nonces", &self.consumed_nonces)?;
        let issued: BTreeSet<_> = self.issued_nonces.iter().cloned().collect();
        if !self
            .consumed_nonces
            .iter()
            .all(|nonce| issued.contains(nonce))
        {
            return Err(ContractError::InvalidValue {
                field: "dispatch_replay_snapshot.consumed_nonces",
                reason: "consumed nonces must be a subset of issued nonces",
            });
        }
        Ok(())
    }
}

impl DispatchPermitAuthority {
    /// Activates one authority instance around Kernel-owned secret material.
    pub fn activate(authority_id: DispatchAuthorityId, key: KernelDispatchKey) -> Self {
        Self {
            authority_id,
            key,
            issued_nonces: BTreeSet::new(),
            consumed_nonces: BTreeSet::new(),
            replay_revision: 1,
        }
    }

    /// Restores an exact Kernel-owned replay fence around the active secret key.
    pub fn recover(
        expected_authority_id: DispatchAuthorityId,
        key: KernelDispatchKey,
        snapshot: DispatchPermitReplaySnapshot,
    ) -> Result<Self, ContractError> {
        expected_authority_id.validate()?;
        snapshot.validate()?;
        if snapshot.authority_id != expected_authority_id {
            return Err(ContractError::DispatchAuthorityMismatch);
        }
        Ok(Self {
            authority_id: expected_authority_id,
            key,
            issued_nonces: snapshot.issued_nonces.into_iter().collect(),
            consumed_nonces: snapshot.consumed_nonces.into_iter().collect(),
            replay_revision: snapshot.replay_revision,
        })
    }

    /// Returns exact replay state for durable fenced recovery by P-07.
    pub fn replay_snapshot(&self) -> DispatchPermitReplaySnapshot {
        DispatchPermitReplaySnapshot {
            authority_id: self.authority_id.clone(),
            issued_nonces: self.issued_nonces.iter().cloned().collect(),
            consumed_nonces: self.consumed_nonces.iter().cloned().collect(),
            replay_revision: self.replay_revision,
        }
    }

    /// Issues one permit bound to the exact immutable intent.
    pub fn issue(
        &mut self,
        intent: &ProcessIntent,
        issuance: PermitIssuance,
    ) -> Result<DispatchPermit, ContractError> {
        intent.validate()?;
        if issuance.state_fence.generation != intent.generation {
            return Err(ContractError::FenceMismatch);
        }
        if self.issued_nonces.contains(&issuance.one_shot_nonce) {
            return Err(ContractError::DuplicateValue {
                field: "one_shot_nonce",
            });
        }
        let mut permit = DispatchPermit {
            schema_version: PROCESS_CONTRACT_SCHEMA_VERSION.to_owned(),
            authority_id: self.authority_id.clone(),
            operation_id: intent.operation_id.clone(),
            process_tree_id: intent.process_tree_id.clone(),
            job_id: intent.job_id.clone(),
            image_id: intent.image_id.clone(),
            session_id: intent.session_id.clone(),
            generation: intent.generation,
            action_lease_ref: issuance.action_lease_ref,
            state_fence: issuance.state_fence,
            expected_revision_heads: issuance.expected_revision_heads,
            effect_digest: intent.effect_digest.clone(),
            issued_at_unix_ms: issuance.issued_at_unix_ms,
            expires_at_unix_ms: issuance.expires_at_unix_ms,
            one_shot_nonce: issuance.one_shot_nonce,
            validation_revision: issuance.validation_revision,
            authentication_tag: String::new(),
            permit_digest: String::new(),
        };
        permit.authentication_tag = keyed_hash_serialized(&self.key.0, &permit.unsigned())?;
        permit.permit_digest = permit_digest(&permit.unsigned(), &permit.authentication_tag)?;
        permit.validate_shape()?;
        let next_revision =
            self.replay_revision
                .checked_add(1)
                .ok_or(ContractError::InvalidValue {
                    field: "replay_revision",
                    reason: "revision overflow",
                })?;
        self.issued_nonces.insert(permit.one_shot_nonce.clone());
        self.replay_revision = next_revision;
        Ok(permit)
    }

    /// Validates fresh P-02 launch evidence and consumes a permit exactly once.
    ///
    /// All checks happen before the nonce ledger mutates. The returned opaque
    /// value is suitable as `V` in P-02's `ValidatedSuspendedJobChild<V>`.
    pub fn validate_and_consume(
        &mut self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
        current: &DispatchValidationContext,
    ) -> Result<ValidatedDispatch, ContractError> {
        request.validate()?;
        observed.validate()?;
        current.validate()?;

        let permit = &request.permit;
        if permit.authority_id != self.authority_id {
            return Err(ContractError::DispatchAuthenticationFailed);
        }
        let expected_tag = keyed_hash_serialized(&self.key.0, &permit.unsigned())?;
        if expected_tag != permit.authentication_tag {
            return Err(ContractError::DispatchAuthenticationFailed);
        }
        if !self.issued_nonces.contains(&permit.one_shot_nonce) {
            return Err(ContractError::DispatchPermitRequired);
        }
        if self.consumed_nonces.contains(&permit.one_shot_nonce) {
            return Err(ContractError::DispatchPermitConsumed);
        }
        if !permit.state_fence.matches(&current.state_fence) {
            return Err(ContractError::StaleStateFence);
        }
        if permit.state_fence.authority_epoch != current.authority_epoch {
            return Err(ContractError::StaleAuthorityEpoch);
        }
        if permit.expected_revision_heads != current.revision_heads {
            return Err(ContractError::StaleRevisionHeads);
        }
        if permit.validation_revision.is_some()
            && permit.validation_revision != Some(current.validation_revision)
        {
            return Err(ContractError::StaleRevisionHeads);
        }
        let now = current.now_unix_ms()?;
        if now < permit.issued_at_unix_ms || now >= permit.expires_at_unix_ms {
            return Err(ContractError::ExpiredDispatchPermit);
        }
        if !permit.matches_intent(&request.intent)
            || observed.process_tree_id != request.intent.process_tree_id
            || observed.job_id != request.intent.job_id
            || observed.image_id != request.intent.image_id
            || observed.session_id != request.intent.session_id
            || observed.generation != request.intent.generation
            || observed.executable_sha256 != request.intent.executable_sha256
        {
            return Err(ContractError::IdentityMismatch);
        }

        let binding = ProcessExecutionBinding {
            operation_id: request.intent.operation_id.clone(),
            process_tree_id: request.intent.process_tree_id.clone(),
            job_id: request.intent.job_id.clone(),
            image_id: request.intent.image_id.clone(),
            session_id: request.intent.session_id.clone(),
            generation: request.intent.generation,
            action_lease_ref: permit.action_lease_ref.clone(),
            authority_id: permit.authority_id.clone(),
            authority_epoch: permit.state_fence.authority_epoch,
            state_fence: permit.state_fence.clone(),
            request_digest: request.invocation_digest.clone(),
            permit_digest: permit.permit_digest.clone(),
            effect_digest: request.intent.effect_digest.clone(),
            validation_revision: current.validation_revision,
        };
        let next_revision =
            self.replay_revision
                .checked_add(1)
                .ok_or(ContractError::InvalidValue {
                    field: "replay_revision",
                    reason: "revision overflow",
                })?;
        let consumed_nonce = permit.one_shot_nonce.clone();
        self.consumed_nonces.insert(consumed_nonce);
        self.replay_revision = next_revision;
        drop(request);
        Ok(ValidatedDispatch {
            binding,
            suspended_identity: observed,
            validated_at_unix_ms: now,
        })
    }

    /// Returns the number of successfully consumed nonces.
    pub fn consumed_permit_count(&self) -> usize {
        self.consumed_nonces.len()
    }

    /// Mints the P-03 half of a P-07-selected recovery capability.
    ///
    /// The caller must supply the persisted exact binding and the current
    /// Kernel observation. This does not duplicate P-07 authority or consume a
    /// dispatch permit; it only creates a capability that can be used by the
    /// recovery start seam after a fresh P-02 observation.
    pub fn issue_recovery_capability(
        &self,
        binding: ProcessExecutionBinding,
        capability_id: impl Into<String>,
        current: &DispatchValidationContext,
    ) -> Result<RecoveryCapability, ContractError> {
        current.validate()?;
        binding.validate()?;
        if binding.authority_id != self.authority_id
            || binding.state_fence != current.state_fence
            || binding.authority_epoch != current.authority_epoch
        {
            return Err(ContractError::RecoveryCapabilityMismatch);
        }
        Ok(RecoveryCapability {
            binding,
            capability_id: validate_opaque_id("recovery_capability_id", capability_id.into())?,
            state_fence: current.state_fence.clone(),
            validation_revision: current.validation_revision,
        })
    }
}

fn validate_replay_nonces(field: &'static str, nonces: &[String]) -> Result<(), ContractError> {
    if nonces.len() > MAX_REPLAY_NONCES {
        return Err(ContractError::LimitExceeded {
            field,
            limit: MAX_REPLAY_NONCES,
        });
    }
    let mut unique = BTreeSet::new();
    for nonce in nonces {
        validate_opaque_id(field, nonce.clone())?;
        if !unique.insert(nonce) {
            return Err(ContractError::DuplicateValue { field });
        }
    }
    Ok(())
}

fn keyed_hash_serialized<T: Serialize>(key: &[u8; 32], value: &T) -> Result<String, ContractError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ContractError::Serialization(error.to_string()))?;
    Ok(blake3::keyed_hash(key, &bytes).to_hex().to_string())
}

fn permit_digest<T: Serialize>(
    unsigned: &T,
    authentication_tag: &str,
) -> Result<String, ContractError> {
    hash_serialized(&(unsigned, authentication_tag))
}
