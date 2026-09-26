use std::sync::Mutex;

use eliot_platform::{KernelActivationNonce, PlatformHandle};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::backend::{BackendReconcileState, CommittedAppend, DurableImage, PreparedAppend};
use crate::model::{
    AppliedOperation, CutoverIntentState, DrainState, EpochEvidence, EpochRetirementRecord,
    HostInstallationEpoch, HostState, HostStateRecord, IdempotencyIdentity, RecordFence,
    RecoveryLineageReason, activation_transition, dependency_transition, drain_transition,
    epoch_transition_is_direct_child_of, kernel_transition, store_rebind_transition,
    wake_transition,
};
use crate::reactive_context::{
    ReactiveContextEnqueueReceipt, ReactiveContextJournalAction, ReactiveContextOperationQuery,
    ReactiveContextPrepareRequest, ReactiveContextPrepareResult, ReactiveContextPreparedEnqueue,
    ReactiveContextQueueError, ReactiveContextQueuePort, ReactiveContextQueueQuery,
    ReactiveContextQueueSnapshot, ReactiveContextReconcileOutcome, ReactiveContextReconcileRequest,
    ReactiveContextRecord, ReactiveContextTransition, ReactiveContextTransitionReceipt,
};
use crate::{JournalBackend, JournalError, ReconcileOutcome};

pub const JOURNAL_MAGIC: &[u8] = b"ELIOT-HOST-STATE\n";
/// Current journal wire revision. Version 1 readiness records did not retain
/// the exact supervision predecessor and are therefore never replayed into a
/// current Host contour. Version 2 carried the retired Host-local
/// `EpochIdentity { lineage, sequence }` spelling; version 3 carries the
/// canonical `EpochId { lineage_id, sequence }` wire shape instead. Version 2
/// frames are rejected explicitly as `UnknownVersion` and are never silently
/// rewritten: recovery proceeds through an explicit new-lineage Host epoch,
/// and rollback to a version 2 reader requires the version 2 journal bytes.
pub const JOURNAL_VERSION: u16 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendDisposition {
    Applied,
    Replayed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendReceipt {
    sequence: u64,
    disposition: AppendDisposition,
    transaction_id: PlatformHandle,
}

impl AppendReceipt {
    /// Sequence assigned by the reducer after durable commit or exact replay.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Whether this call applied a new frame or replayed an existing one.
    pub const fn disposition(&self) -> AppendDisposition {
        self.disposition
    }

    /// Stable transaction identity used for UNKNOWN reconciliation.
    pub fn transaction_id(&self) -> &PlatformHandle {
        &self.transaction_id
    }
}

/// Exact cutover operation identity whose applied `EpochRetirement` record is
/// wanted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochRetirementQuery {
    /// Canonical operation identity of the retirement record.
    pub operation: IdempotencyIdentity,
}

/// Retirement resolved by the journal owner under one exact operation
/// identity.
///
/// Construction is restricted to this crate: every field is private, there is
/// no public constructor, no `Default`, and no deserialization. The only
/// producer is [`HostStateJournal::query_epoch_retirement`], so possessing an
/// observation means this journal durably applied that record. A caller cannot
/// mint one, and a presented [`AppendReceipt`] remains a lookup hint that must
/// be checked against [`Self::transaction_id`] rather than believed on
/// presence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochRetirementObservation {
    record: EpochRetirementRecord,
    transaction_id: PlatformHandle,
}

impl EpochRetirementObservation {
    /// Exact record this journal applied, including its own fence and evidence.
    pub const fn record(&self) -> &EpochRetirementRecord {
        &self.record
    }

    /// Canonical operation identity the record was applied under.
    pub const fn operation(&self) -> &IdempotencyIdentity {
        &self.record.operation
    }

    /// Owner-recorded retirement instant.
    pub const fn retired_at(&self) -> &PlatformHandle {
        &self.record.retired_at
    }

    /// Retired Host installation/activation epoch.
    pub const fn retired_host(&self) -> &HostInstallationEpoch {
        &self.record.retired_host
    }

    /// Owner-supplied evidence digests bound to the retirement.
    pub fn retirement_evidence_refs(&self) -> &[PlatformHandle] {
        &self.record.retirement_evidence_refs
    }

    /// Host/activation fence the record was accepted under.
    pub const fn fence(&self) -> &RecordFence {
        &self.record.fence
    }

    /// Transaction identity this journal owner computes for the resolved
    /// record. A caller-supplied receipt for the same operation is proof of the
    /// append only when it names exactly this identity.
    pub const fn transaction_id(&self) -> &PlatformHandle {
        &self.transaction_id
    }
}

/// Typed failures of the owner-resolved epoch-retirement lookup.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum EpochRetirementQueryError {
    /// The enclosing Host journal could not be read, or the owner could not
    /// recompute the resolved record's transaction identity.
    #[error("host-state journal: {0}")]
    Journal(#[from] JournalError),
    /// The query named a malformed operation identity.
    #[error("epoch retirement query invalid: {0}")]
    Invalid(String),
    /// This journal log applied no retirement for that exact operation.
    #[error("epoch retirement was not found for the named operation")]
    NotFound,
    /// This journal log holds more than one retirement for that exact
    /// operation. That is a contradiction about durable state, never a choice
    /// between candidates, so it is reported instead of resolved.
    #[error("epoch retirement is contradictory for the named operation")]
    Contradictory,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameHeader {
    version: u16,
    sequence: u64,
    length: u64,
    checksum: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplyDisposition {
    Applied,
    Replayed(u64),
}

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, JournalError> {
    serde_json::to_vec(value).map_err(|error| JournalError::Invalid(error.to_string()))
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, JournalError> {
    serde_json::from_slice(bytes).map_err(|error| JournalError::Invalid(error.to_string()))
}

fn decode_record_for_replay(bytes: &[u8]) -> Result<HostStateRecord, JournalError> {
    let mut wire: serde_json::Value = decode(bytes)?;
    match serde_json::from_value(wire.clone()) {
        Ok(record) => Ok(record),
        Err(strict_error) => {
            let nonce_slot = wire
                .pointer_mut("/kernel/one_time_nonce/nonce_ref")
                .ok_or_else(|| JournalError::Invalid(strict_error.to_string()))?;
            let nonce_text = nonce_slot
                .as_str()
                .ok_or_else(|| JournalError::Invalid(strict_error.to_string()))?
                .to_owned();
            let legacy_nonce = PlatformHandle::new(nonce_text)
                .map_err(|_| JournalError::Invalid(strict_error.to_string()))?;
            if KernelActivationNonce::new(legacy_nonce.clone()).is_ok() {
                return Err(JournalError::Invalid(strict_error.to_string()));
            }
            *nonce_slot = serde_json::Value::String("0".repeat(64));
            let mut record: HostStateRecord = serde_json::from_value(wire)
                .map_err(|error| JournalError::Invalid(error.to_string()))?;
            let HostStateRecord::Kernel(kernel) = &mut record else {
                return Err(JournalError::Invalid(strict_error.to_string()));
            };
            kernel.restore_legacy_nonce_for_replay(legacy_nonce)?;
            Ok(record)
        }
    }
}

/// Lowercase SHA-256 digest used for frame integrity and idempotency binding.
fn checksum(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn record_checksum(record: &HostStateRecord) -> Result<String, JournalError> {
    record.validate()?;
    Ok(checksum(&json(record)?))
}

pub(crate) fn journal_transaction_id(
    record: &HostStateRecord,
    record_checksum: &str,
) -> Result<PlatformHandle, JournalError> {
    transaction_id_for(record.operation(), &record.fence().host, record_checksum)
}

fn transaction_id_for(
    operation: &IdempotencyIdentity,
    host: &HostInstallationEpoch,
    record_checksum: &str,
) -> Result<PlatformHandle, JournalError> {
    let host_binding = checksum(&json(host)?);
    PlatformHandle::new(format!(
        "p05:{host_binding}:{}:{}:{}",
        operation.operation_id.as_str(),
        operation.idempotency_key.as_str(),
        record_checksum
    ))
    .map_err(|error| JournalError::Invalid(error.to_string()))
}

fn frame(sequence: u64, record: &HostStateRecord) -> Result<Vec<u8>, JournalError> {
    let payload = json(record)?;
    let length = u64::try_from(payload.len()).map_err(|_| JournalError::Sequence)?;
    let header = json(&FrameHeader {
        version: JOURNAL_VERSION,
        sequence,
        length,
        checksum: checksum(&payload),
    })?;
    let mut bytes = Vec::with_capacity(JOURNAL_MAGIC.len() + header.len() + payload.len() + 2);
    bytes.extend_from_slice(JOURNAL_MAGIC);
    bytes.extend_from_slice(&header);
    bytes.push(b'\n');
    bytes.extend_from_slice(&payload);
    bytes.push(b'\n');
    Ok(bytes)
}

fn replay(
    bytes: &[u8],
    host: HostInstallationEpoch,
    retained: Vec<EpochEvidence>,
) -> Result<HostState, JournalError> {
    host.validate()?;
    let mut state = HostState::new(host, retained);
    for frame in scan_frames(bytes)? {
        apply(
            &mut state,
            &frame.record,
            frame.header.sequence,
            &frame.header.checksum,
        )?;
        state.sequence = frame.header.sequence;
        state.last_checksum = Some(frame.header.checksum);
    }
    Ok(state)
}

/// Scans only the durable frame envelope and decodes its record.
///
/// This intentionally has no reducer state. Callers that need semantic
/// validation must do so in their own boundary, and the replay path advances
/// its reducer only after `apply` succeeds.
struct ScannedFrame<'a> {
    raw: &'a [u8],
    header: FrameHeader,
    record: HostStateRecord,
}

fn scan_frames(bytes: &[u8]) -> Result<Vec<ScannedFrame<'_>>, JournalError> {
    let mut offset = 0_usize;
    let mut expected_sequence = 1_u64;
    let mut frames = Vec::new();
    while offset < bytes.len() {
        let frame_start = offset;
        let magic_end = offset
            .checked_add(JOURNAL_MAGIC.len())
            .ok_or(JournalError::Torn { offset })?;
        if bytes.get(offset..magic_end) != Some(JOURNAL_MAGIC) {
            return Err(JournalError::Torn { offset });
        }
        offset = magic_end;
        let header_end = bytes[offset..]
            .iter()
            .position(|byte| *byte == b'\n')
            .and_then(|delta| offset.checked_add(delta))
            .ok_or(JournalError::Torn { offset })?;
        let header: FrameHeader = decode(&bytes[offset..header_end])?;
        if header.version != JOURNAL_VERSION {
            return Err(JournalError::UnknownVersion {
                version: header.version,
            });
        }
        offset = header_end
            .checked_add(1)
            .ok_or(JournalError::Torn { offset: header_end })?;
        let payload_length =
            usize::try_from(header.length).map_err(|_| JournalError::Torn { offset })?;
        let end = offset
            .checked_add(payload_length)
            .ok_or(JournalError::Torn { offset })?;
        let newline = end.checked_add(1).ok_or(JournalError::Torn { offset })?;
        if newline > bytes.len() || bytes.get(end) != Some(&b'\n') {
            return Err(JournalError::Torn { offset });
        }
        let payload = &bytes[offset..end];
        if checksum(payload) != header.checksum {
            return Err(JournalError::Checksum {
                sequence: header.sequence,
            });
        }
        if header.sequence != expected_sequence {
            return Err(JournalError::Sequence);
        }
        let record = decode_record_for_replay(payload)?;
        frames.push(ScannedFrame {
            raw: &bytes[frame_start..newline],
            header,
            record,
        });
        if newline < bytes.len() {
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(JournalError::Sequence)?;
        }
        offset = newline;
    }
    Ok(frames)
}

pub(crate) struct FrameBinding {
    pub(crate) operation: IdempotencyIdentity,
    pub(crate) record_checksum: String,
    pub(crate) payload_digest: String,
}

pub(crate) fn frame_bindings(
    epoch_bytes: &[u8],
    host: &HostInstallationEpoch,
) -> Result<Vec<FrameBinding>, JournalError> {
    host.validate()?;
    let mut bindings = Vec::new();
    for frame in scan_frames(epoch_bytes)? {
        frame.record.validate()?;
        if frame.record.fence().host != *host {
            return Err(JournalError::StaleFence);
        }
        bindings.push(FrameBinding {
            operation: frame.record.operation().clone(),
            record_checksum: frame.header.checksum,
            payload_digest: checksum(frame.raw),
        });
    }
    Ok(bindings)
}

// Keeping the record union in one exhaustive match makes the one-writer state
// mutation boundary auditable; individual transition laws live in `model`.
#[allow(clippy::too_many_lines)]
fn apply(
    state: &mut HostState,
    record: &HostStateRecord,
    sequence: u64,
    applied_record_checksum: &str,
) -> Result<ApplyDisposition, JournalError> {
    record.validate()?;
    if record.fence().host != state.host {
        return Err(JournalError::StaleFence);
    }
    if let Some(existing) = state
        .applied_operations
        .iter()
        .find(|item| item.identity == *record.operation())
    {
        return if existing.checksum == applied_record_checksum {
            Ok(ApplyDisposition::Replayed(existing.sequence))
        } else {
            Err(JournalError::IdempotencyConflict)
        };
    }
    if !matches!(record, HostStateRecord::Activation(_)) {
        let active_generation = state
            .activation
            .as_ref()
            .map(|activation| &activation.fence.activation_generation)
            .ok_or(JournalError::StaleFence)?;
        let active_activation_id = state
            .activation
            .as_ref()
            .map(|activation| &activation.activation_id)
            .ok_or(JournalError::StaleFence)?;
        if &record.fence().activation_id != active_activation_id {
            return Err(JournalError::StaleFence);
        }
        if active_generation != &record.fence().activation_generation {
            return Err(JournalError::StaleFence);
        }
    }

    match record {
        HostStateRecord::Activation(next) => {
            let new_generation = state.activation.as_ref().is_some_and(|current| {
                current.fence.activation_generation != next.fence.activation_generation
            });
            activation_transition(
                state.activation.as_ref(),
                next,
                state.drain_commit.is_some(),
            )?;
            if new_generation {
                if let Some(current) = state.kernel.take() {
                    state.kernel_history.push(current.clone());
                    state.prior_kernel = Some(current);
                } else {
                    state.prior_kernel = state.prior_kernel.take();
                }
                state.prior_kernel_unknown = state.prior_kernel_unknown
                    || (state.prior_kernel.is_none()
                        && state.retained_epochs.iter().any(|item| !item.retired));
                state.kernel = None;
                state.dependencies.clear();
                state.drain = None;
                state.drain_commit = None;
                state.wakes.clear();
                if let Some(queue) = state.reactive_context.as_mut() {
                    queue.advance_generation()?;
                }
                state.clean_marker = None;
            }
            state.activation = Some(next.clone());
        }
        HostStateRecord::Kernel(next) => {
            let activation_identity = state
                .activation
                .as_ref()
                .map(|activation| &activation.activation_id)
                .ok_or(JournalError::StaleFence)?;
            if &next.activation_identity != activation_identity {
                return Err(JournalError::StaleFence);
            }
            if state.prior_kernel_unknown {
                return Err(JournalError::Invalid(
                    "Kernel prior disposition is unknown; manual recovery is required".into(),
                ));
            }
            if state.kernel.is_none()
                && let Some(prior) = state.prior_kernel.as_ref()
            {
                // T6-E4-A host scalar closure: scalar process ordering is
                // intra-lineage only. Cross-lineage numeric ordering is
                // forbidden, so the scalar `>` below is gated on the typed
                // epoch tuple proving same lineage via `relation_to`. The
                // typed direct-child check remains the admission authority;
                // this gate ensures a larger scalar from another lineage can
                // never satisfy `authority_advances` on its own.
                let same_kernel_lineage = !matches!(
                    next.kernel_generation
                        .current
                        .relation_to(&prior.kernel_generation.current),
                    eliot_contracts::EpochRelation::UnrelatedLineage
                );
                let authority_advances = same_kernel_lineage
                    && prior
                        .process
                        .as_ref()
                        .zip(next.process.as_ref())
                        .is_some_and(|(prior_process, candidate_process)| {
                            candidate_process.authority_epoch.value()
                                > prior_process.authority_epoch.value()
                        });
                if !epoch_transition_is_direct_child_of(
                    &next.kernel_generation,
                    &prior.kernel_generation,
                )? || next.state
                    != eliot_runtime_contracts::KernelActivationState::ShadowNoAuthority
                    || !authority_advances
                {
                    return Err(JournalError::StaleFence);
                }
            }
            let same_activation_restart = state
                .kernel
                .as_ref()
                .is_some_and(|current| current.kernel_generation != next.kernel_generation);
            let exact_prior = if same_activation_restart {
                state.kernel.as_ref()
            } else {
                state.prior_kernel.as_ref()
            };
            match exact_prior {
                None if matches!(
                    next.prior_kernel_disposition,
                    crate::PriorKernelDisposition::NoPriorKernel
                ) => {}
                Some(prior) if next.prior_kernel_disposition.binds_to(prior) => {}
                _ => {
                    return Err(JournalError::Invalid(
                        "Kernel prior disposition does not bind preserved reducer context".into(),
                    ));
                }
            }
            if next.state == eliot_runtime_contracts::KernelActivationState::NonceIssued
                && state
                    .kernel_history
                    .iter()
                    .chain(state.prior_kernel.iter())
                    .any(|prior| {
                        prior.one_time_nonce.nonce_ref().is_some()
                            && prior.one_time_nonce.nonce_ref() == next.one_time_nonce.nonce_ref()
                    })
            {
                return Err(JournalError::Invalid(
                    "direct-child Kernel generation requires a fresh activation nonce".into(),
                ));
            }
            kernel_transition(state.kernel.as_ref(), next)?;
            if same_activation_restart && let Some(current) = state.kernel.clone() {
                state.kernel_history.push(current.clone());
                state.prior_kernel = Some(current);
            }
            state.kernel = Some(next.clone());
            state.clean_marker = None;
        }
        HostStateRecord::Dependency(next) => {
            let index = state
                .dependencies
                .iter()
                .position(|item| item.dependency == next.dependency);
            dependency_transition(index.map(|index| &state.dependencies[index]), next)?;
            if let Some(index) = index {
                state.dependencies[index] = next.clone();
            } else {
                state.dependencies.push(next.clone());
            }
            state.clean_marker = None;
        }
        HostStateRecord::Drain(next) => {
            // One attempt link exists per drain attempt, and it is checked
            // before the transition law, exactly as the `CutoverIntent` arm
            // checks its `expected_predecessor`. The projection keeps exactly
            // one `DrainRecord`, so without this the reducer cannot tell
            // attempt N from attempt N+1 and a stale or concurrent re-arm would
            // be applied as if it were the current attempt:
            //  * a `Cancelled -> Requested` re-arm is admitted only when it
            //    names the exact record checksum of the `Cancelled`
            //    predecessor it re-arms. An absent link is a typed refusal
            //    (that edge is a re-arm, so the link is mandatory) and a
            //    mismatching link is an identity conflict, never a silent
            //    re-arm of some other attempt;
            //  * every other drain edge continues the current attempt, so an
            //    unexpected link there is an identity conflict as well.
            // `drain_transition` below keeps ownership of the
            // `drain_generation` equality rule and the legal-transition set;
            // this is an additional check, not a replacement.
            if let Some(current) = state.drain.as_ref() {
                let rearm = matches!(
                    (current.state, next.state),
                    (DrainState::Cancelled, DrainState::Requested)
                );
                if rearm {
                    let Some(predecessor) = next.expected_predecessor.as_deref() else {
                        return Err(JournalError::IllegalTransition {
                            machine: "drain",
                            from: format!("{:?}", current.state),
                            to: format!("{:?}::without-expected-predecessor", next.state),
                        });
                    };
                    let current_checksum =
                        record_checksum(&HostStateRecord::Drain(current.clone()))?;
                    if predecessor != current_checksum {
                        return Err(JournalError::IdempotencyConflict);
                    }
                } else if next.expected_predecessor.is_some() {
                    return Err(JournalError::IdempotencyConflict);
                }
            } else if next.expected_predecessor.is_some() {
                // A first attempt has no predecessor to name.
                return Err(JournalError::IdempotencyConflict);
            }
            drain_transition(state.drain.as_ref(), next, state.drain_commit.is_some())?;
            state.drain = Some(next.clone());
            state.clean_marker = None;
        }
        HostStateRecord::DrainCommit(next) => {
            let drain = state
                .drain
                .as_ref()
                .ok_or_else(|| JournalError::IllegalTransition {
                    machine: "drain",
                    from: "NONE".into(),
                    to: "COMMITTED".into(),
                })?;
            if drain.state != crate::DrainState::Draining
                || drain.drain_generation != next.drain_generation
                || state.drain_commit.is_some()
                || state.activation.as_ref().map(|value| value.state)
                    != Some(crate::ActivationState::Draining)
            {
                return Err(JournalError::IllegalTransition {
                    machine: "drain",
                    from: format!("{:?}", drain.state),
                    to: "COMMITTED".into(),
                });
            }
            state.drain_commit = Some(next.clone());
            state.clean_marker = None;
        }
        HostStateRecord::Wake(next) => {
            let index = state
                .wakes
                .iter()
                .position(|item| item.wake_id == next.wake_id);
            wake_transition(index.map(|index| &state.wakes[index]), next)?;
            if let Some(index) = index {
                state.wakes[index] = next.clone();
            } else {
                state.wakes.push(next.clone());
            }
            state.clean_marker = None;
        }
        HostStateRecord::WakeCancellationBatch(next) => {
            // Validate every compare-and-swap member against the same locked
            // snapshot before replacing any WakeRecord.  A stale later
            // target therefore cannot leave an earlier target applied.
            let mut indexes = Vec::with_capacity(next.entries.len());
            for entry in &next.entries {
                let index = state
                    .wakes
                    .iter()
                    .position(|item| item.wake_id == entry.wake.wake_id)
                    .ok_or(JournalError::StaleFence)?;
                let current_checksum =
                    record_checksum(&HostStateRecord::Wake(state.wakes[index].clone()))?;
                if current_checksum != entry.expected_record_checksum.as_str() {
                    return Err(JournalError::StaleFence);
                }
                wake_transition(Some(&state.wakes[index]), &entry.wake)?;
                indexes.push(index);
            }
            for (index, entry) in indexes.into_iter().zip(&next.entries) {
                state.wakes[index] = entry.wake.clone();
            }
            state.clean_marker = None;
        }
        HostStateRecord::Observation(next) => {
            state.observations.push(next.clone());
            state.clean_marker = None;
        }
        HostStateRecord::ReadinessObservation(next) => {
            let active = state.kernel.as_ref().ok_or(JournalError::StaleFence)?;
            let active_checksum = record_checksum(&HostStateRecord::Kernel(active.clone()))?;
            next.validate_against(active, &active_checksum)?;
            if state.readiness_observations.iter().any(|existing| {
                existing.probe_request_digest == next.probe_request_digest
                    || existing.ready_receipt_digest == next.ready_receipt_digest
            }) {
                return Err(JournalError::Invalid(
                    "readiness probe request and receipt digests must be fresh".into(),
                ));
            }
            state.readiness_observations.push(next.clone());
            state.clean_marker = None;
        }
        HostStateRecord::StoreRebind(next) => {
            let key = (next.operation_id.as_str(), next.request_digest.as_str());
            let index = state.store_rebinds.iter().position(|item| {
                item.operation_id.as_str() == key.0 && item.request_digest.as_str() == key.1
            });
            store_rebind_transition(index.map(|i| &state.store_rebinds[i]), next)?;
            if let Some(idx) = index {
                state.store_rebinds[idx] = next.clone();
            } else {
                state.store_rebinds.push(next.clone());
            }
            state.clean_marker = None;
        }
        HostStateRecord::ReactiveContext(next) => {
            crate::reactive_context::apply_record(&mut state.reactive_context, next, sequence)?;
            state.clean_marker = None;
        }
        HostStateRecord::CleanMarker(next) => {
            let genesis_without_runtime_contour = state
                .activation
                .as_ref()
                .is_some_and(|activation| activation.state == crate::ActivationState::Stopped)
                && state.kernel.is_none()
                && state.kernel_history.is_empty()
                && state.prior_kernel.is_none()
                && !state.prior_kernel_unknown
                && state.dependencies.is_empty()
                && state.drain.is_none()
                && state.drain_commit.is_none()
                && state.wakes.is_empty()
                && state.observations.is_empty()
                && state.readiness_observations.is_empty()
                && state.store_rebinds.is_empty();
            // A durable `Pending` cutover intent is an outstanding owner
            // effect: a clean marker would licence a new Host epoch lineage
            // while an activation is authorized but unapplied, which is
            // exactly the "activation without a durable intent" hazard the
            // intent record exists to close. A terminal intent is settled
            // history and does not block shutdown.
            let cutover_settled = state
                .pending_cutover
                .as_ref()
                .is_none_or(|intent| intent.state != CutoverIntentState::Pending);
            let reactive_context_clean = state
                .reactive_context
                .as_ref()
                .is_none_or(crate::ReactiveContextQueueState::clean_for_drain);
            if next.manifest.schema_version != JOURNAL_VERSION
                || next.manifest.last_sequence != state.sequence
                || next.manifest.last_checksum.as_str()
                    != state.last_checksum.as_deref().unwrap_or("GENESIS")
                || (state.activation.as_ref().map(|value| value.state)
                    != Some(crate::ActivationState::StoppedClean)
                    && !genesis_without_runtime_contour)
                || !reactive_context_clean
                || !cutover_settled
            {
                return Err(JournalError::Invalid(
                    "clean marker does not cover a cleanly stopped journal".into(),
                ));
            }
            state.clean_marker = Some(next.clone());
        }
        HostStateRecord::EpochRetirement(next) => {
            if state.host.installation != next.retired_host.installation
                || !state
                    .retained_epochs
                    .iter()
                    .any(|item| item.host == next.retired_host && !item.retired)
            {
                return Err(JournalError::StaleFence);
            }
            for evidence in &mut state.retained_epochs {
                if evidence.host == next.retired_host {
                    evidence.retired = true;
                }
            }
            state.retired_epochs.push(next.retired_host.clone());
            // Retain the record itself, not only the retired epoch, so the
            // exact cutover operation that produced the retirement stays
            // resolvable. This admits nothing new: the record already passed
            // this crate's own `validate()` at the top of `apply` and every
            // fence check above, and the `!item.retired` gate above is what
            // bounds this projection — one entry per retired epoch, so a
            // second retirement of the same epoch is refused rather than
            // appended.
            state.epoch_retirements.push(next.clone());
            state.clean_marker = None;
        }
        HostStateRecord::CutoverIntent(next) => {
            // A durable cutover intent is a small state machine: `Pending`
            // authorizes the activation CAS, and exactly one terminal
            // disposition (`Committed`/`Failed`) closes it. The rules, in
            // order:
            //  * a terminal disposition is only accepted after a durable
            //    `Pending` for the same operation, installation, request
            //    digest, fence and bindings;
            //  * a `Pending` for the *same* operation must match the
            //    outstanding intent exactly;
            //  * a `Pending` for a *distinct* operation replaces the
            //    projection only once the previous intent is terminal, so an
            //    outstanding authorized-but-unapplied intent is never
            //    discarded by another cutover;
            //  * a terminal disposition is never revised: a refused operation
            //    stays refused, and a new attempt is a new operation identity.
            if let Some(current) = state.pending_cutover.as_ref() {
                let same_operation = current.cutover_operation == next.cutover_operation
                    && current.installation == next.installation
                    && current.request_digest == next.request_digest;
                if next.state == CutoverIntentState::Pending {
                    if same_operation {
                        if current.fence != next.fence {
                            return Err(JournalError::IdempotencyConflict);
                        }
                        if current.state != CutoverIntentState::Pending {
                            return Err(JournalError::Invalid(
                                "cutover intent disposition is already terminal".into(),
                            ));
                        }
                        if current.expected_predecessor != next.expected_predecessor
                            || current.target_generation != next.target_generation
                            || current.target_build_digest != next.target_build_digest
                            || current.target_config_digest != next.target_config_digest
                            || current.user_broker_ref != next.user_broker_ref
                        {
                            return Err(JournalError::IdempotencyConflict);
                        }
                    } else if current.state == CutoverIntentState::Pending {
                        return Err(JournalError::IdempotencyConflict);
                    }
                } else {
                    if !same_operation || current.fence != next.fence {
                        return Err(JournalError::IdempotencyConflict);
                    }
                    if current.state != CutoverIntentState::Pending {
                        return Err(JournalError::Invalid(
                            "cutover intent disposition is already terminal".into(),
                        ));
                    }
                    if current.expected_predecessor != next.expected_predecessor
                        || current.target_generation != next.target_generation
                        || current.target_build_digest != next.target_build_digest
                        || current.target_config_digest != next.target_config_digest
                        || current.user_broker_ref != next.user_broker_ref
                    {
                        return Err(JournalError::IdempotencyConflict);
                    }
                }
            } else if next.state != CutoverIntentState::Pending {
                // The activation CAS may only run after a `Pending` record is
                // durable, so a terminal disposition with no durable intent is
                // refused at this boundary rather than trusted.
                return Err(JournalError::Invalid(
                    "cutover intent terminal disposition without a durable intent".into(),
                ));
            }
            state.pending_cutover = Some(next.clone());
            state.clean_marker = None;
        }
    }
    state.applied_operations.push(AppliedOperation {
        identity: record.operation().clone(),
        checksum: applied_record_checksum.to_owned(),
        sequence,
    });
    Ok(ApplyDisposition::Applied)
}

struct LoadedEpochs {
    states: Vec<HostState>,
    evidence: Vec<EpochEvidence>,
}

fn load_epochs(
    image: &DurableImage,
    tolerate_corruption: bool,
) -> Result<LoadedEpochs, JournalError> {
    let mut states = Vec::with_capacity(image.epochs.len());
    let mut epoch_evidence = Vec::with_capacity(image.epochs.len());
    for (index, epoch) in image.epochs.iter().enumerate() {
        epoch.host.validate()?;
        if image.epochs[..index].iter().any(|item| {
            item.host == epoch.host || item.host.epoch.current == epoch.host.epoch.current
        }) {
            return Err(JournalError::Invalid("duplicate durable host epoch".into()));
        }
        match replay(&epoch.bytes, epoch.host.clone(), epoch_evidence.clone()) {
            Ok(state) => {
                for retired in &state.retired_epochs {
                    for evidence in &mut epoch_evidence {
                        if evidence.host == *retired {
                            evidence.retired = true;
                        }
                    }
                }
                epoch_evidence.push(EpochEvidence {
                    host: state.host.clone(),
                    last_sequence: state.sequence,
                    last_checksum: state.last_checksum.clone(),
                    forensic_digest: checksum(&epoch.bytes),
                    replay_verified: true,
                    retired: false,
                });
                states.push(state);
            }
            Err(_error) if tolerate_corruption => {
                epoch_evidence.push(EpochEvidence {
                    host: epoch.host.clone(),
                    last_sequence: 0,
                    last_checksum: None,
                    forensic_digest: checksum(&epoch.bytes),
                    replay_verified: false,
                    retired: false,
                });
            }
            Err(error) => return Err(error),
        }
    }
    Ok(LoadedEpochs {
        states,
        evidence: epoch_evidence,
    })
}

fn validate_committed_receipts(
    image: &DurableImage,
    loaded: &LoadedEpochs,
    requested_host: &HostInstallationEpoch,
    recovery_reason: Option<RecoveryLineageReason>,
) -> Result<(), JournalError> {
    let mut binding_cache: Vec<Option<Vec<FrameBinding>>> =
        (0..image.epochs.len()).map(|_| None).collect();
    for receipt in &image.receipts {
        let mut matching_epoch = None;
        for (index, epoch) in image.epochs.iter().enumerate() {
            if epoch.host == receipt.host && matching_epoch.replace(index).is_some() {
                return Err(JournalError::Invalid(
                    "committed receipt does not name exactly one durable host epoch".into(),
                ));
            }
        }
        let Some(epoch_index) = matching_epoch else {
            return Err(JournalError::Invalid(
                "committed receipt does not name exactly one durable host epoch".into(),
            ));
        };
        let mut matching_evidence = None;
        for evidence in &loaded.evidence {
            if evidence.host == receipt.host && matching_evidence.replace(evidence).is_some() {
                return Err(JournalError::Invalid(
                    "committed receipt does not name exactly one epoch evidence record".into(),
                ));
            }
        }
        let Some(evidence) = matching_evidence else {
            return Err(JournalError::Invalid(
                "committed receipt does not name exactly one epoch evidence record".into(),
            ));
        };
        if transaction_id_for(&receipt.operation, &receipt.host, &receipt.record_checksum)?
            != receipt.transaction_id
        {
            return Err(JournalError::IdempotencyConflict);
        }
        if !evidence.replay_verified {
            if recovery_reason == Some(RecoveryLineageReason::Corruption)
                && receipt.host != *requested_host
            {
                // The receipt remains retained evidence, but it is not
                // authoritative and cannot participate in reconciliation for
                // this newly recovered Host lineage.
                continue;
            }
            return Err(JournalError::Invalid(
                "committed receipt belongs to an unverified host epoch".into(),
            ));
        }

        if binding_cache[epoch_index].is_none() {
            let epoch = &image.epochs[epoch_index];
            binding_cache[epoch_index] = Some(frame_bindings(&epoch.bytes, &epoch.host)?);
        }
        let bindings = binding_cache[epoch_index]
            .as_ref()
            .ok_or_else(|| JournalError::Invalid("missing epoch frame bindings".into()))?;
        if !bindings.iter().any(|binding| {
            binding.operation == receipt.operation
                && binding.record_checksum == receipt.record_checksum
                && binding.payload_digest == receipt.payload_digest
        }) {
            return Err(JournalError::IdempotencyConflict);
        }
    }
    Ok(())
}

fn state_for_host(
    image: &DurableImage,
    host: &HostInstallationEpoch,
) -> Result<HostState, JournalError> {
    let recovery_reason = host.recovery.as_ref().map(|recovery| recovery.reason);
    let tolerate_corruption = recovery_reason == Some(RecoveryLineageReason::Corruption);
    let loaded = load_epochs(image, tolerate_corruption)?;
    validate_committed_receipts(image, &loaded, host, recovery_reason)?;
    let states = loaded.states;
    let all_evidence = loaded.evidence;
    if let Some(mut current) = states.iter().find(|state| &state.host == host).cloned() {
        if all_evidence
            .iter()
            .any(|item| item.host == *host && item.retired)
        {
            return Err(JournalError::StaleFence);
        }
        current.retained_epochs = all_evidence
            .into_iter()
            .filter(|item| item.host != *host)
            .collect();
        return Ok(current);
    }
    if image.epochs.is_empty() {
        if host.epoch.parent.is_some() {
            return Err(JournalError::RecoveryRequiresNewEpoch);
        }
        return Ok(HostState::new(host.clone(), Vec::new()));
    }
    if host.epoch.parent.is_none() {
        if host.recovery.is_none()
            || host.epoch.current.sequence.get() != 1
            || all_evidence
                .iter()
                .any(|item| item.host.installation != host.installation)
            || all_evidence
                .iter()
                .any(|item| item.host.epoch.current.lineage_id == host.epoch.current.lineage_id)
        {
            return Err(JournalError::RecoveryRequiresNewEpoch);
        }
        let mut recovered = HostState::new(host.clone(), all_evidence);
        recovered.prior_kernel_unknown = true;
        return Ok(recovered);
    }
    if host.recovery.is_some() {
        return Err(JournalError::RecoveryRequiresNewEpoch);
    }
    let Some(parent_id) = &host.epoch.parent else {
        return Err(JournalError::RecoveryRequiresNewEpoch);
    };
    let parent = states
        .iter()
        .find(|state| state.host.epoch.current == *parent_id)
        .ok_or(JournalError::RecoveryRequiresNewEpoch)?;
    if !host.is_direct_child_of(&parent.host)?
        || all_evidence
            .iter()
            .any(|item| item.host == parent.host && item.retired)
        || states
            .iter()
            .any(|state| state.host.epoch.parent.as_ref() == Some(parent_id) && state.host != *host)
    {
        return Err(JournalError::RecoveryRequiresNewEpoch);
    }
    let mut next = HostState::new(host.clone(), all_evidence);
    next.prior_kernel = parent
        .kernel
        .clone()
        .or_else(|| parent.prior_kernel.clone());
    next.prior_kernel_unknown = parent.prior_kernel_unknown;
    Ok(next)
}

fn validate_committed_append(
    committed: &CommittedAppend,
    state: &HostState,
) -> Result<u64, JournalError> {
    if committed.host != state.host {
        return Err(JournalError::StaleFence);
    }
    if committed.payload_digest.trim().is_empty()
        || transaction_id_for(
            &committed.operation,
            &committed.host,
            &committed.record_checksum,
        )? != committed.transaction_id
    {
        return Err(JournalError::IdempotencyConflict);
    }
    let operation = state
        .applied_operations
        .iter()
        .find(|item| item.identity == committed.operation)
        .ok_or_else(|| {
            JournalError::Invalid(
                "committed transaction operation is absent from its durable Host epoch".into(),
            )
        })?;
    if operation.checksum != committed.record_checksum {
        return Err(JournalError::IdempotencyConflict);
    }
    Ok(operation.sequence)
}

fn validate_expected_commit(
    committed: &CommittedAppend,
    expected: &PreparedAppend,
) -> Result<(), JournalError> {
    if committed.host != expected.host {
        return Err(JournalError::StaleFence);
    }
    if committed.transaction_id != expected.transaction_id
        || committed.operation != expected.operation
        || committed.record_checksum != expected.record_checksum
        || committed.payload_digest != expected.payload_digest
    {
        return Err(JournalError::IdempotencyConflict);
    }
    Ok(())
}

fn validate_prepared_descriptor<B: JournalBackend>(
    backend: &mut B,
    transaction_id: &PlatformHandle,
    host: &HostInstallationEpoch,
) -> Result<(), JournalError> {
    let pending = backend.prepared_appends().map_err(map_backend_error)?;
    if pending.iter().any(|item| item.host != *host) {
        return Err(JournalError::StaleFence);
    }
    let matches: Vec<_> = pending
        .iter()
        .filter(|item| item.transaction_id == *transaction_id)
        .collect();
    match matches.as_slice() {
        [item] if item.host == *host && item.transaction_id == *transaction_id => Ok(()),
        [] => Err(JournalError::Invalid(
            "prepared reconcile descriptor is missing".into(),
        )),
        _ => Err(JournalError::Invalid(
            "prepared reconcile descriptor is duplicated".into(),
        )),
    }
}

pub struct HostStateJournal<B> {
    backend: Mutex<B>,
    state: Mutex<HostState>,
}

impl<B: JournalBackend> HostStateJournal<B> {
    #[allow(clippy::needless_pass_by_value)]
    pub fn open(mut backend: B, host: HostInstallationEpoch) -> Result<Self, JournalError> {
        host.validate()?;
        let image = backend.load().map_err(map_backend_error)?;
        let state = state_for_host(&image, &host)?;
        Ok(Self {
            backend: Mutex::new(backend),
            state: Mutex::new(state),
        })
    }

    pub fn replay_bytes(
        bytes: &[u8],
        host: HostInstallationEpoch,
    ) -> Result<HostState, JournalError> {
        replay(bytes, host, Vec::new())
    }

    pub fn snapshot(&self) -> Result<HostState, JournalError> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| JournalError::Synchronization)
    }

    /// Returns durable prepared transaction descriptors without attempting to
    /// replay, retry, or otherwise deliver any transaction.
    pub fn pending_transactions(&self) -> Result<Vec<PreparedAppend>, JournalError> {
        let host = self
            .state
            .lock()
            .map_err(|_| JournalError::Synchronization)?
            .host
            .clone();
        let pending = self
            .backend
            .lock()
            .map_err(|_| JournalError::Synchronization)?
            .prepared_appends()
            .map_err(map_backend_error)?;
        if pending.iter().any(|item| item.host != host) {
            return Err(JournalError::StaleFence);
        }
        Ok(pending)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn append(&self, record: HostStateRecord) -> Result<AppendReceipt, JournalError> {
        if matches!(&record, HostStateRecord::ReadinessObservation(_)) {
            return Err(JournalError::Invalid(
                "readiness observations require exact approved-contour admission".into(),
            ));
        }
        self.append_inner(record)
    }

    pub fn append_readiness_observation(
        &self,
        observation: crate::KernelReadinessObservationRecord,
        expected: &crate::ReadinessApprovedContour,
    ) -> Result<AppendReceipt, JournalError> {
        observation.validate_approved_contour(expected)?;
        self.append_inner(HostStateRecord::ReadinessObservation(observation))
    }

    pub fn prepare_reactive_context(
        &self,
        request: ReactiveContextPrepareRequest,
    ) -> Result<ReactiveContextPrepareResult, ReactiveContextQueueError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ReactiveContextQueueError::Journal(JournalError::Synchronization))?;
        crate::reactive_context::prepare(state.reactive_context.as_ref(), request)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn commit_reactive_context(
        &self,
        prepared: ReactiveContextPreparedEnqueue,
    ) -> Result<ReactiveContextEnqueueReceipt, ReactiveContextQueueError> {
        if !matches!(
            &prepared.record.action,
            ReactiveContextJournalAction::Enqueue(_)
        ) {
            return Err(ReactiveContextQueueError::Invalid(
                "prepared enqueue token does not contain an enqueue action".into(),
            ));
        }
        let host_record = HostStateRecord::ReactiveContext(prepared.record.clone());
        let checksum = record_checksum(&host_record)?;
        if checksum != prepared.record_checksum {
            return Err(ReactiveContextQueueError::IdentityConflict);
        }
        let transaction_id = journal_transaction_id(&host_record, &checksum)?;
        if transaction_id != prepared.transaction_id {
            return Err(ReactiveContextQueueError::IdentityConflict);
        }
        let journal = self.append(host_record)?;
        let state = self.snapshot()?;
        let entry = state
            .reactive_context
            .as_ref()
            .and_then(|queue| queue.committed_entry(&prepared.record.operation))
            .ok_or(ReactiveContextQueueError::NotFound)?;
        Ok(ReactiveContextEnqueueReceipt { journal, entry })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn compare_and_transition(
        &self,
        transition: ReactiveContextTransition,
    ) -> Result<ReactiveContextTransitionReceipt, ReactiveContextQueueError> {
        let record = ReactiveContextRecord {
            schema_version: crate::REACTIVE_CONTEXT_QUEUE_SCHEMA_VERSION,
            fence: transition.fence.clone(),
            operation: transition.mutation.clone(),
            expected_queue_revision: transition.expected_queue_revision,
            action: ReactiveContextJournalAction::Transition(transition.clone()),
        };
        let journal = self.append(HostStateRecord::ReactiveContext(record))?;
        let state = self.snapshot()?;
        let entry = state
            .reactive_context
            .as_ref()
            .and_then(|queue| queue.committed_entry(&transition.target))
            .ok_or(ReactiveContextQueueError::NotFound)?;
        Ok(ReactiveContextTransitionReceipt { journal, entry })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn load_reactive_context_queue(
        &self,
        query: ReactiveContextQueueQuery,
    ) -> Result<ReactiveContextQueueSnapshot, ReactiveContextQueueError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ReactiveContextQueueError::Journal(JournalError::Synchronization))?;
        let queue = state.reactive_context.clone().unwrap_or_default();
        crate::reactive_context::snapshot(&queue, &query)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn query_reactive_context_operation(
        &self,
        query: ReactiveContextOperationQuery,
    ) -> Result<crate::ReactiveContextQueueEntry, ReactiveContextQueueError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ReactiveContextQueueError::Journal(JournalError::Synchronization))?;
        state
            .reactive_context
            .as_ref()
            .and_then(|queue| queue.committed_entry(&query.operation))
            .ok_or(ReactiveContextQueueError::NotFound)
    }

    /// Exact `EpochRetirement` record this journal applied for one canonical
    /// operation identity, or a typed absence.
    ///
    /// This is the owner half of retirement resolution: the record is selected
    /// from the durable log this journal replayed, under the exact operation
    /// identity the caller named, and the transaction identity is recomputed
    /// here rather than taken from the caller. A caller-supplied
    /// [`AppendReceipt`] is therefore only a lookup hint — it may select this
    /// record, and it is never the proof that this journal applied it.
    pub fn query_epoch_retirement(
        &self,
        query: &EpochRetirementQuery,
    ) -> Result<EpochRetirementObservation, EpochRetirementQueryError> {
        query
            .operation
            .validate()
            .map_err(|error| EpochRetirementQueryError::Invalid(error.to_string()))?;
        let state = self
            .state
            .lock()
            .map_err(|_| EpochRetirementQueryError::Journal(JournalError::Synchronization))?;
        let mut matching = state
            .epoch_retirements
            .iter()
            .filter(|record| record.operation == query.operation);
        let Some(retirement) = matching.next().cloned() else {
            return Err(EpochRetirementQueryError::NotFound);
        };
        if matching.next().is_some() {
            // Two applied retirements under one canonical operation identity
            // contradict the log. Picking the first would resolve a
            // contradiction about durable state by convenience.
            return Err(EpochRetirementQueryError::Contradictory);
        }
        let record = HostStateRecord::EpochRetirement(retirement.clone());
        let transaction_id = journal_transaction_id(&record, &record_checksum(&record)?)?;
        Ok(EpochRetirementObservation {
            record: retirement,
            transaction_id,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn reconcile_reactive_context(
        &self,
        request: ReactiveContextReconcileRequest,
    ) -> Result<ReactiveContextReconcileOutcome, ReactiveContextQueueError> {
        let (outcome, committed_operation) =
            self.reconcile_with_descriptor(&request.transaction_id)?;
        if matches!(outcome, ReconcileOutcome::Committed)
            && committed_operation.as_ref() != Some(&request.operation)
        {
            return Err(ReactiveContextQueueError::IdentityConflict);
        }
        let state = self.snapshot()?;
        let entry = state
            .reactive_context
            .as_ref()
            .and_then(|queue| queue.committed_entry(&request.operation));
        crate::reactive_context::map_reconcile(outcome, entry)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn append_inner(&self, record: HostStateRecord) -> Result<AppendReceipt, JournalError> {
        record.validate_live_admission()?;
        let record_checksum = record_checksum(&record)?;
        let transaction_id = journal_transaction_id(&record, &record_checksum)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| JournalError::Synchronization)?;
        let sequence = state
            .sequence
            .checked_add(1)
            .ok_or(JournalError::Sequence)?;
        let mut next = state.clone();
        match apply(&mut next, &record, sequence, &record_checksum)? {
            ApplyDisposition::Replayed(original) => {
                return Ok(AppendReceipt {
                    sequence: original,
                    disposition: AppendDisposition::Replayed,
                    transaction_id,
                });
            }
            ApplyDisposition::Applied => {}
        }
        let bytes = frame(sequence, &record)?;
        let prepared = PreparedAppend {
            transaction_id: transaction_id.clone(),
            host: state.host.clone(),
            operation: record.operation().clone(),
            record_checksum: record_checksum.clone(),
            payload_digest: checksum(&bytes),
        };
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| JournalError::Synchronization)?;
        match backend
            .reconcile(&transaction_id)
            .map_err(map_backend_error)?
        {
            BackendReconcileState::Committed(committed) => {
                validate_expected_commit(&committed, &prepared)?;
                let image = backend.load().map_err(map_backend_error)?;
                let recovered = state_for_host(&image, &state.host)?;
                let original = validate_committed_append(&committed, &recovered)?;
                *state = recovered;
                return Ok(AppendReceipt {
                    sequence: original,
                    disposition: AppendDisposition::Replayed,
                    transaction_id,
                });
            }
            BackendReconcileState::Prepared => {
                validate_prepared_descriptor(&mut *backend, &transaction_id, &state.host)?;
                return Err(JournalError::OutcomeUnknown { transaction_id });
            }
            BackendReconcileState::Absent => {}
        }
        if let Err(error) = backend.prepare(&prepared) {
            return Err(persist_error(error, &transaction_id));
        }
        backend
            .append_prepared(&transaction_id, &bytes)
            .map_err(|error| persist_error(error, &transaction_id))?;
        backend
            .flush(&transaction_id)
            .map_err(|error| persist_error(error, &transaction_id))?;
        backend
            .sync(&transaction_id)
            .map_err(|error| persist_error(error, &transaction_id))?;
        backend
            .commit(&transaction_id)
            .map_err(|error| persist_error(error, &transaction_id))?;
        next.sequence = sequence;
        next.last_checksum = Some(record_checksum);
        *state = next;
        Ok(AppendReceipt {
            sequence,
            disposition: AppendDisposition::Applied,
            transaction_id,
        })
    }

    pub fn reconcile(
        &self,
        transaction_id: &PlatformHandle,
    ) -> Result<ReconcileOutcome, JournalError> {
        Ok(self.reconcile_with_descriptor(transaction_id)?.0)
    }

    pub(crate) fn reconcile_with_descriptor(
        &self,
        transaction_id: &PlatformHandle,
    ) -> Result<(ReconcileOutcome, Option<IdempotencyIdentity>), JournalError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| JournalError::Synchronization)?;
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| JournalError::Synchronization)?;
        match backend
            .reconcile(transaction_id)
            .map_err(map_backend_error)?
        {
            BackendReconcileState::Committed(committed) => {
                if committed.host != state.host {
                    return Err(JournalError::StaleFence);
                }
                let image = backend.load().map_err(map_backend_error)?;
                let recovered = state_for_host(&image, &state.host)?;
                validate_committed_append(&committed, &recovered)?;
                let operation = committed.operation.clone();
                *state = recovered;
                Ok((ReconcileOutcome::Committed, Some(operation)))
            }
            BackendReconcileState::Prepared => {
                validate_prepared_descriptor(&mut *backend, transaction_id, &state.host)?;
                Ok((ReconcileOutcome::StillUnknown, None))
            }
            BackendReconcileState::Absent => Ok((ReconcileOutcome::NotCommitted, None)),
        }
    }

    pub fn into_backend(self) -> Result<B, JournalError> {
        self.backend
            .into_inner()
            .map_err(|_| JournalError::Synchronization)
    }

    #[cfg(test)]
    pub(crate) fn poison_state_for_test(&self) {
        std::thread::scope(|scope| {
            let state = &self.state;
            let _ = scope
                .spawn(move || {
                    let _guard = state.lock().unwrap_or_else(|_| unreachable!());
                    panic!("poison fixture");
                })
                .join();
        });
    }

    #[cfg(test)]
    pub(crate) fn set_sequence_for_test(&self, sequence: u64) {
        self.state
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .sequence = sequence;
    }
}

impl<B: JournalBackend> ReactiveContextQueuePort for HostStateJournal<B> {
    fn prepare_or_replay(
        &self,
        request: ReactiveContextPrepareRequest,
    ) -> Result<ReactiveContextPrepareResult, ReactiveContextQueueError> {
        self.prepare_reactive_context(request)
    }

    fn commit_enqueued(
        &self,
        prepared: ReactiveContextPreparedEnqueue,
    ) -> Result<ReactiveContextEnqueueReceipt, ReactiveContextQueueError> {
        self.commit_reactive_context(prepared)
    }

    fn compare_and_transition(
        &self,
        transition: ReactiveContextTransition,
    ) -> Result<ReactiveContextTransitionReceipt, ReactiveContextQueueError> {
        Self::compare_and_transition(self, transition)
    }

    fn load_attempt_queue(
        &self,
        query: ReactiveContextQueueQuery,
    ) -> Result<ReactiveContextQueueSnapshot, ReactiveContextQueueError> {
        self.load_reactive_context_queue(query)
    }

    fn query_operation(
        &self,
        query: ReactiveContextOperationQuery,
    ) -> Result<crate::ReactiveContextQueueEntry, ReactiveContextQueueError> {
        self.query_reactive_context_operation(query)
    }

    fn reconcile_operation(
        &self,
        request: ReactiveContextReconcileRequest,
    ) -> Result<ReactiveContextReconcileOutcome, ReactiveContextQueueError> {
        self.reconcile_reactive_context(request)
    }
}

pub fn readonly_project_host_state(image: &DurableImage) -> Result<HostState, JournalError> {
    if image.epochs.is_empty() {
        return Err(JournalError::Invalid(
            "journal has no durable epochs".into(),
        ));
    }
    let mut successes = Vec::new();
    let mut first_torn: Option<JournalError> = None;
    for epoch in &image.epochs {
        match state_for_host(image, &epoch.host) {
            Ok(state) => successes.push(state),
            Err(error) => match &error {
                JournalError::Torn { .. }
                | JournalError::Checksum { .. }
                | JournalError::Sequence
                | JournalError::UnknownVersion { .. }
                    if first_torn.is_none() =>
                {
                    first_torn = Some(error);
                }
                _ => {}
            },
        }
    }
    if let Some(error) = first_torn {
        return Err(error);
    }
    if successes.is_empty() {
        let _ = load_epochs(image, false)?;
        return Err(JournalError::Invalid(
            "no valid HostState projection".into(),
        ));
    }
    successes
        .into_iter()
        .max_by_key(|state| state.sequence)
        .ok_or_else(|| JournalError::Invalid("no projection".into()))
}

fn persist_error(error: crate::BackendError, transaction_id: &PlatformHandle) -> JournalError {
    match error {
        crate::BackendError::PlanGap { dependency } => JournalError::PlanGap { dependency },
        crate::BackendError::Unknown(_) => JournalError::OutcomeUnknown {
            transaction_id: transaction_id.clone(),
        },
        other => JournalError::Backend(other),
    }
}

fn map_backend_error(error: crate::BackendError) -> JournalError {
    match error {
        crate::BackendError::PlanGap { dependency } => JournalError::PlanGap { dependency },
        other => JournalError::Backend(other),
    }
}
