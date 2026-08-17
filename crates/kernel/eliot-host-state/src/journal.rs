use std::sync::Mutex;

use eliot_platform::PlatformHandle;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::backend::{BackendReconcileState, CommittedAppend, DurableImage, PreparedAppend};
use crate::model::{
    AppliedOperation, EpochEvidence, HostInstallationEpoch, HostState, HostStateRecord,
    IdempotencyIdentity, RecoveryLineageReason, activation_transition, dependency_transition,
    drain_transition, kernel_transition, wake_transition,
};
use crate::{JournalBackend, JournalError, ReconcileOutcome};

pub const JOURNAL_MAGIC: &[u8] = b"ELIOT-HOST-STATE\n";
pub const JOURNAL_VERSION: u16 = 1;

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

/// Lowercase SHA-256 digest used for frame integrity and idempotency binding.
fn checksum(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn record_checksum(record: &HostStateRecord) -> Result<String, JournalError> {
    record.validate()?;
    Ok(checksum(&json(record)?))
}

fn transaction_id(
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
        let record: HostStateRecord = decode(payload)?;
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
    record_checksum: &str,
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
        return if existing.checksum == record_checksum {
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
                state.kernel = None;
                state.dependencies.clear();
                state.drain = None;
                state.drain_commit = None;
                state.wakes.clear();
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
            kernel_transition(state.kernel.as_ref(), next)?;
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
        HostStateRecord::Observation(next) => {
            state.observations.push(next.clone());
            state.clean_marker = None;
        }
        HostStateRecord::CleanMarker(next) => {
            if next.manifest.schema_version != JOURNAL_VERSION
                || next.manifest.last_sequence != state.sequence
                || next.manifest.last_checksum.as_str()
                    != state.last_checksum.as_deref().unwrap_or("GENESIS")
                || state.activation.as_ref().map(|value| value.state)
                    != Some(crate::ActivationState::StoppedClean)
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
            state.clean_marker = None;
        }
    }
    state.applied_operations.push(AppliedOperation {
        identity: record.operation().clone(),
        checksum: record_checksum.to_owned(),
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
            || host.epoch.current.sequence != 1
            || all_evidence
                .iter()
                .any(|item| item.host.installation != host.installation)
            || all_evidence
                .iter()
                .any(|item| item.host.epoch.current.lineage == host.epoch.current.lineage)
        {
            return Err(JournalError::RecoveryRequiresNewEpoch);
        }
        return Ok(HostState::new(host.clone(), all_evidence));
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
    Ok(HostState::new(host.clone(), all_evidence))
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
        self.backend
            .lock()
            .map_err(|_| JournalError::Synchronization)?
            .prepared_appends()
            .map_err(map_backend_error)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn append(&self, record: HostStateRecord) -> Result<AppendReceipt, JournalError> {
        record.validate()?;
        let record_checksum = record_checksum(&record)?;
        let transaction_id = transaction_id(&record, &record_checksum)?;
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
                *state = recovered;
                Ok(ReconcileOutcome::Committed)
            }
            BackendReconcileState::Prepared => Ok(ReconcileOutcome::StillUnknown),
            BackendReconcileState::Absent => Ok(ReconcileOutcome::NotCommitted),
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
