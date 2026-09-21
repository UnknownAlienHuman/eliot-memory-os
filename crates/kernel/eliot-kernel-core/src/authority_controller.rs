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
    AuthoritySnapshotReceipt, KernelAuthoritySnapshot, OperationIdentity, OperationalRecordContext,
    OperationalRecordInput, OperationalRecoveryStore, StateFenceSnapshot,
};
use eliot_process::{
    DispatchAuthorityId, DispatchPermit, DispatchPermitAuthority, DispatchValidationContext,
    KernelDispatchKey, OriginChallenge, OriginChallengeAuthority, OriginChallengeRequest,
    OriginControlGrant, OriginControlPresentation, PermitIssuance,
    ProcessExecutionAdmissionRequest, ProcessIntent, ProcessOwnerBinding, ProcessRequest,
    ProcessStartReceipt, RecoveryCapability, SuspendedProcessIdentity, ValidatedDispatch,
};

pub use crate::authority_snapshot::{
    AuthoritySnapshotBinding, AuthoritySnapshotBindingWire, DispatchSnapshotCodec,
    KernelAuthorityReplaySnapshot, SealedAuthoritySnapshot,
};
use crate::error::{KernelError, KernelResult};

const ORIGIN_AUTHORITY_ID: &str = "kernel-origin-authority";

/// Durable replay projection for one admitted process start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessExecutionReplayRecord {
    /// Canonical digest of the inert admission request.
    pub admission_digest: String,
    /// Exact authenticated caller binding that owns the operation.
    pub owner: ProcessOwnerBinding,
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
    /// Loads the durable operation owner before status/cancel/reconcile.
    fn load_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
    ) -> KernelResult<Option<ProcessExecutionReplayRecord>>;

    /// Atomically reserves an operation before any process effect.
    fn begin_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
        admission_digest: &str,
        owner: &ProcessOwnerBinding,
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

/// The sole P-07 owner of one P-03 process dispatch-permit authority.
pub struct ProcessDispatchAuthorityController {
    authority_id: DispatchAuthorityId,
    authority: DispatchPermitAuthority,
    origin_authority: OriginChallengeAuthority,
    store: Arc<dyn OperationalRecoveryStore>,
    codec: Arc<dyn DispatchSnapshotCodec>,
    snapshot_receipt: Option<AuthoritySnapshotReceipt>,
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
        let origin_key = key.clone_for_sibling_authority();
        let authority = DispatchPermitAuthority::activate(authority_id.clone(), key);
        let origin_authority =
            OriginChallengeAuthority::activate(origin_authority_id(), origin_key);
        Self {
            authority_id,
            authority,
            origin_authority,
            store,
            codec,
            snapshot_receipt: None,
            poisoned: false,
        }
    }

    /// Activates a fresh authority and commits its empty replay fence before
    /// the caller can expose the controller to any gateway.
    ///
    /// A clean first boot has no replay snapshot to restore.  The initial
    /// snapshot is nevertheless durable evidence of the exact authority
    /// binding and is the linearization point that makes a later restart safe.
    pub fn activate_and_persist_initial(
        authority_id: DispatchAuthorityId,
        key: KernelDispatchKey,
        store: Arc<dyn OperationalRecoveryStore>,
        codec: Arc<dyn DispatchSnapshotCodec>,
        binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<Self> {
        ensure_binding(&authority_id, binding)?;
        let mut controller = Self::activate(authority_id, key, store, codec);
        controller.persist_snapshot(binding)?;
        Ok(controller)
    }

    /// Checks whether ORS contains the exact metadata-bound replay snapshot
    /// for an authority without consuming the caller's secret key.
    ///
    /// This is used to choose between clean activation and restart recovery.
    /// An existing but mismatched record is an integrity failure, never an
    /// invitation to overwrite it with a fresh empty snapshot.
    pub fn exact_snapshot_present(
        authority_id: &DispatchAuthorityId,
        store: &dyn OperationalRecoveryStore,
        binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<bool> {
        ensure_binding(authority_id, binding)?;
        let subject = subject_id(authority_id)?;
        let Some(recovered) = store.load_authority_snapshot(&subject)? else {
            return Ok(false);
        };
        let record = recovered.snapshot().record();
        if record.subject_id != subject
            || record.record_id != *binding.record_id()
            || record.authority_epoch != *binding.authority_epoch()
            || record.state_fence != *binding.state_fence()
            || record.created_at_ms != binding.created_at_ms()
            || record.cleanup_after_ms != binding.cleanup_after_ms()
        {
            return Err(KernelError::FenceMismatch);
        }
        Ok(true)
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
            || record.record_id != *binding.record_id()
            || record.authority_epoch != *binding.authority_epoch()
            || record.state_fence != *binding.state_fence()
            || record.created_at_ms != binding.created_at_ms()
            || record.cleanup_after_ms != binding.cleanup_after_ms()
        {
            return Err(KernelError::FenceMismatch);
        }
        let replay = codec.open(&record.payload, binding)?;
        let origin_key = key.clone_for_sibling_authority();
        let authority =
            DispatchPermitAuthority::recover(authority_id.clone(), key, replay.dispatch)?;
        let origin_authority =
            OriginChallengeAuthority::recover(origin_authority_id(), origin_key, replay.origin)?;
        Ok(Self {
            authority_id,
            authority,
            origin_authority,
            store,
            codec,
            snapshot_receipt: Some(recovered.receipt().clone()),
            poisoned: false,
        })
    }

    /// Returns the exact process authority identity without exposing a key.
    #[must_use]
    pub fn authority_id(&self) -> &DispatchAuthorityId {
        &self.authority_id
    }

    /// Issues one Kernel-owned process-origin challenge and durably records
    /// its nonce before exposing it to the daemon transport.
    pub fn issue_origin_challenge(
        &mut self,
        request: &OriginChallengeRequest,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<OriginChallenge> {
        self.ensure_operational(binding)?;
        self.ensure_origin_request_binding(request, binding)?;
        let challenge = self
            .origin_authority
            .issue(request, issued_at_unix_ms, expires_at_unix_ms)
            .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
        self.persist_snapshot(binding)?;
        Ok(challenge)
    }

    /// Consumes one Kernel-owned process-origin presentation and durably
    /// records its one-shot nonce before returning the grant proof.
    pub fn decide_origin_control(
        &mut self,
        presentation: &OriginControlPresentation,
        now_unix_ms: u64,
        binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<OriginControlGrant> {
        self.ensure_operational(binding)?;
        self.ensure_origin_request_binding(presentation.request(), binding)?;
        let active_epoch = binding_current_epoch(binding)?;
        let grant = self
            .origin_authority
            .decide(presentation, &active_epoch, now_unix_ms)
            .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
        self.persist_snapshot(binding)?;
        Ok(grant)
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
        let snapshot = KernelAuthorityReplaySnapshot {
            dispatch: self.authority.replay_snapshot(),
            origin: self.origin_authority.replay_snapshot(),
        };
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
        match self
            .store
            .commit_authority_snapshot_cas(snapshot, self.snapshot_receipt.as_ref())
        {
            Ok(receipt) => {
                self.snapshot_receipt = Some(receipt.clone());
                Ok(receipt)
            }
            Err(error) => {
                self.poisoned = true;
                Err(error.into())
            }
        }
    }

    fn ensure_origin_request_binding(
        &self,
        request: &OriginChallengeRequest,
        binding: &AuthoritySnapshotBinding,
    ) -> KernelResult<()> {
        request
            .validate()
            .map_err(|error| KernelError::DependencyUnavailable(error.to_string()))?;
        binding
            .state_fence()
            .validate_against_epoch(&request.state_fence().authority_epoch)
            .map_err(|_| KernelError::FenceMismatch)?;
        let captured = StateFenceSnapshot::capture(
            request.state_fence(),
            request.state_fence().authority_epoch.sequence.get(),
        )
        .map_err(|_| KernelError::FenceMismatch)?;
        if captured != *binding.state_fence() {
            return Err(KernelError::FenceMismatch);
        }
        Ok(())
    }
}

fn origin_authority_id() -> DispatchAuthorityId {
    match DispatchAuthorityId::new(ORIGIN_AUTHORITY_ID) {
        Ok(value) => value,
        Err(_) => unreachable!("the fixed origin authority identity is valid"),
    }
}

fn binding_current_epoch(
    binding: &AuthoritySnapshotBinding,
) -> KernelResult<eliot_contracts::EpochId> {
    let fence: eliot_contracts::StateFence =
        serde_json::from_str(&binding.state_fence().canonical_json)
            .map_err(|_| KernelError::FenceMismatch)?;
    fence.validate().map_err(|_| KernelError::FenceMismatch)?;
    binding
        .state_fence()
        .validate_against_epoch(&fence.authority_epoch)
        .map_err(|_| KernelError::FenceMismatch)?;
    Ok(fence.authority_epoch)
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
