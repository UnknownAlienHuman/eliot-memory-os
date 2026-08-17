//! P-07's single owner for provider-neutral process dispatch authority.
//!
//! [`ProcessDispatchAuthorityController`] is the only production composition
//! point that owns an [`eliot_process::DispatchPermitAuthority`].  It routes
//! issue, consuming validation, and recovery-capability issuance through that
//! object and journals its replay snapshot through P-06.
//!
//! ORS is deliberately kept opaque here.  The injected [`DispatchSnapshotCodec`]
//! is the object-safe P-01/platform seam that knows how to seal and resolve the
//! payload.  P-07 never implements substitute crypto, stores plaintext in ORS,
//! exposes a key, or lets a caller mint a recovery capability.

use std::sync::Arc;

use eliot_ors::{
    AuthoritySnapshotReceipt, EpochLineage, KernelAuthoritySnapshot, OperationIdentity,
    OperationalRecordContext, OperationalRecordInput, OperationalRecoveryStore, RecoveryPayload,
    StateFenceSnapshot,
};
use eliot_platform::SecretReference;
use eliot_process::{
    DispatchAuthorityId, DispatchPermit, DispatchPermitAuthority, DispatchPermitReplaySnapshot,
    DispatchValidationContext, KernelDispatchKey, PermitIssuance, ProcessExecutionAdmissionRequest,
    ProcessIntent, ProcessRequest, ProcessStartReceipt, RecoveryCapability,
    SuspendedProcessIdentity, ValidatedDispatch,
};

use crate::error::{KernelError, KernelResult};

/// Durable replay projection for one admitted process start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessExecutionReplayRecord {
    /// Canonical digest of the inert admission request.
    pub admission_digest: String,
    /// Durable operation disposition.
    pub state: ProcessExecutionReplayState,
    /// Exact start receipt returned after resume, when completion is proven.
    pub receipt: Option<ProcessStartReceipt>,
}

/// Durable one-shot start disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessExecutionReplayState {
    /// Reservation was durably acquired before any child effect.
    Reserved,
    /// Child start and receipt persistence are proven.
    Completed,
    /// Delivery/effect outcome is unknown and must reconcile by operation id.
    Unknown,
}

/// Result of the atomic durable start reservation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ProcessExecutionReplayBegin {
    /// This caller owns the only reservation for a new operation.
    Acquired,
    /// An earlier reservation or completion already exists.
    Existing(ProcessExecutionReplayRecord),
}

/// External durable store for process start replay projections.
///
/// Kernel requires this binding for production execution. There is no default
/// in-memory implementation, because replay safety must survive caller and
/// Kernel restart.
pub trait ProcessExecutionReplayStore: Send + Sync {
    /// Atomically reserves an operation before any process effect.
    fn begin_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
        admission_digest: &str,
    ) -> KernelResult<ProcessExecutionReplayBegin>;

    /// Persists the projection at the one-shot start linearization point.
    fn persist_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
        record: ProcessExecutionReplayRecord,
    ) -> KernelResult<()>;
}

/// Computes the canonical replay identity for an inert admission request.
pub fn process_admission_digest(
    request: &ProcessExecutionAdmissionRequest,
) -> KernelResult<String> {
    let bytes = serde_json::to_vec(request).map_err(|error| {
        KernelError::DependencyUnavailable(format!(
            "process admission digest serialization: {error}"
        ))
    })?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Exact ORS metadata required to bind one process-authority replay snapshot.
///
/// The authority id is retained as process-contract identity, while the epoch
/// lineage and State Fence are compared byte-for-byte with the recovered ORS
/// record before its opaque payload is handed to the codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritySnapshotBinding {
    authority_id: DispatchAuthorityId,
    record_id: OperationIdentity,
    authority_epoch: EpochLineage,
    state_fence: StateFenceSnapshot,
    created_at_ms: i64,
    cleanup_after_ms: Option<i64>,
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

    fn into_parts(self) -> (SecretReference, Vec<u8>) {
        (self.key, self.ciphertext)
    }
}

/// Object-safe P-01/platform port for authority-snapshot encryption and
/// decryption.
///
/// This trait intentionally has no default implementation: P-07 cannot fake
/// encryption truth.  The `open` input remains the opaque ORS payload, and
/// the implementation must reject an unexpected authority id, epoch, or
/// State Fence rather than returning a plausible snapshot.
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

/// The sole P-07 owner of one P-03 process dispatch-permit authority.
pub struct ProcessDispatchAuthorityController {
    authority_id: DispatchAuthorityId,
    authority: DispatchPermitAuthority,
    store: Arc<dyn OperationalRecoveryStore>,
    codec: Arc<dyn DispatchSnapshotCodec>,
    poisoned: bool,
}

impl ProcessDispatchAuthorityController {
    /// Activates a fresh process authority around caller-supplied secret bytes.
    ///
    /// The key is moved directly into P-03 and is never retained or exposed by
    /// this controller.
    pub fn activate(
        authority_id: DispatchAuthorityId,
        key: KernelDispatchKey,
        store: Arc<dyn OperationalRecoveryStore>,
        codec: Arc<dyn DispatchSnapshotCodec>,
    ) -> Self {
        let authority = DispatchPermitAuthority::activate(authority_id.clone(), key);
        Self {
            authority_id,
            authority,
            store,
            codec,
            poisoned: false,
        }
    }

    /// Restores one exact replay snapshot from P-06 before exposing the
    /// controller to callers.
    ///
    /// The caller supplies the platform key but never receives it back.  A
    /// missing snapshot, wrong subject, wrong authority identity, stale epoch
    /// or stale State Fence fails closed.
    pub fn restore(
        authority_id: DispatchAuthorityId,
        key: KernelDispatchKey,
        store: Arc<dyn OperationalRecoveryStore>,
        codec: Arc<dyn DispatchSnapshotCodec>,
        binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<Self> {
        ensure_binding(&authority_id, binding)?;
        let subject = subject_id(&authority_id)?;
        let recovered = store.load_authority_snapshot(&subject)?.ok_or_else(|| {
            KernelError::RecoveryUnavailable("authority snapshot is absent".to_owned())
        })?;
        let record = recovered.snapshot().record();
        if record.subject_id != subject
            || record.authority_epoch != *binding.authority_epoch()
            || record.state_fence != *binding.state_fence()
        {
            return Err(KernelError::FenceMismatch);
        }
        let replay = codec.open(&record.payload, binding)?;
        let authority = DispatchPermitAuthority::recover(authority_id.clone(), key, replay)?;
        Ok(Self {
            authority_id,
            authority,
            store,
            codec,
            poisoned: false,
        })
    }

    /// Returns the exact process authority identity without exposing a key.
    #[must_use]
    pub fn authority_id(&self) -> &DispatchAuthorityId {
        &self.authority_id
    }

    /// Issues one permit and durably journals its replay state.
    pub fn issue(
        &mut self,
        intent: &ProcessIntent,
        issuance: PermitIssuance,
        binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<DispatchPermit> {
        self.ensure_operational(binding)?;
        let permit = self.authority.issue(intent, issuance)?;
        self.persist_snapshot(binding)?;
        Ok(permit)
    }

    /// Validates fresh P-02 evidence, consumes one permit, and journals the
    /// resulting replay fence before returning the opaque validated dispatch.
    pub fn validate_and_consume(
        &mut self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
        current: &DispatchValidationContext,
        binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<ValidatedDispatch> {
        self.ensure_operational(binding)?;
        let validated = self
            .authority
            .validate_and_consume(request, observed, current)?;
        self.persist_snapshot(binding)?;
        Ok(validated)
    }

    /// Issues the P-03 recovery capability only after P-07 selected and bound
    /// the durable record.  No caller-supplied capability can enter P-03.
    pub fn issue_recovery_capability(
        &self,
        binding: &AuthoritySnapshotBinding,
        process_binding: eliot_process::ProcessExecutionBinding,
        capability_id: impl Into<String>,
        current: &DispatchValidationContext,
    ) -> KernelResult<RecoveryCapability> {
        self.ensure_binding(binding)?;
        Ok(self
            .authority
            .issue_recovery_capability(process_binding, capability_id, current)?)
    }

    fn ensure_operational(&self, binding: &AuthoritySnapshotBinding) -> KernelResult<()> {
        if self.poisoned {
            return Err(KernelError::DependencyUnavailable(
                "process authority replay journal is fenced after a persistence failure".to_owned(),
            ));
        }
        self.ensure_binding(binding)
    }

    fn ensure_binding(&self, binding: &AuthoritySnapshotBinding) -> KernelResult<()> {
        ensure_binding(&self.authority_id, binding)
    }

    fn persist_snapshot(
        &mut self,
        binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<AuthoritySnapshotReceipt> {
        let snapshot = self.authority.replay_snapshot();
        let sealed = match self.codec.seal(&snapshot, binding) {
            Ok(value) => value,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let (key, ciphertext) = sealed.into_parts();
        let context = OperationalRecordContext {
            record_id: binding.record_id.clone(),
            subject_id: subject_id(&self.authority_id)?,
            authority_epoch: binding.authority_epoch.clone(),
            state_fence: binding.state_fence.clone(),
            created_at_ms: binding.created_at_ms,
            cleanup_after_ms: binding.cleanup_after_ms,
        };
        let input = match OperationalRecordInput::encrypted(context, key, ciphertext) {
            Ok(value) => value,
            Err(error) => {
                self.poisoned = true;
                return Err(error.into());
            }
        };
        let snapshot = match KernelAuthoritySnapshot::new(input) {
            Ok(value) => value,
            Err(error) => {
                self.poisoned = true;
                return Err(error.into());
            }
        };
        match self.store.commit_authority_snapshot(snapshot) {
            Ok(receipt) => Ok(receipt),
            Err(error) => {
                self.poisoned = true;
                Err(error.into())
            }
        }
    }
}

fn subject_id(authority_id: &DispatchAuthorityId) -> KernelResult<OperationIdentity> {
    OperationIdentity::new(authority_id.as_str()).map_err(KernelError::from)
}

fn ensure_binding(
    authority_id: &DispatchAuthorityId,
    binding: &AuthoritySnapshotBinding,
) -> KernelResult<()> {
    if binding.authority_id() != authority_id {
        return Err(KernelError::RecoveryUnavailable(
            "authority snapshot binding identity mismatch".to_owned(),
        ));
    }
    if binding.state_fence().observed_authority_epoch != binding.authority_epoch().current.epoch {
        return Err(KernelError::FenceMismatch);
    }
    Ok(())
}
