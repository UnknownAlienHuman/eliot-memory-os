//! Kernel-owned cross-wrapper capacity and physical-lifetime state for #1814.
//!
//! Reservations are tied to the original authenticated request and admission.
//! A reservation is released only after the same retained native Job reports
//! an empty process tree; there is no lease timeout or caller completion bit.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_instrument_api::InstrumentAdmissionGrant;
use eliot_ipc::{PeerIdentity, RequestIdentity, kernel_client::AuthenticatedKernelResponse};
use eliot_process::{
    KernelDispatchGrant, ProcessEvidence, ProcessExecutionError, ProcessIntent,
    StreamTransportStatus,
};

use crate::{
    InstrumentStageGrantRequest, InstrumentStageStartedRequest, InstrumentStageStartedResponse,
    InstrumentStageTerminalRequest, InstrumentStageTerminalResponse,
};

/// Refusal from the Kernel-owned shared instrument capacity/lifetime owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InstrumentStageRuntimeError {
    /// A caller, identity, grant, or physical observation did not match the
    /// original admitted operation.
    #[error("instrument stage runtime binding was refused")]
    Binding,
    /// The admitted per-kind concurrency limit is currently occupied.
    #[error("instrument stage per-kind concurrency limit is occupied")]
    Capacity,
    /// A physical OS owner could not verify the job or its members.
    #[error("instrument stage physical owner could not be verified")]
    Physical,
    /// Shared state was poisoned and cannot safely issue or release capacity.
    #[error("instrument stage runtime state is unavailable")]
    Unavailable,
}

impl From<InstrumentStageRuntimeError> for ProcessExecutionError {
    fn from(_: InstrumentStageRuntimeError) -> Self {
        Self::Unavailable("Kernel refused instrument stage runtime observation".to_owned())
    }
}

/// Required P-04 lifecycle observation port. Implementations must send these
/// exact carriers over the authenticated Kernel client and validate the
/// authenticated response's operation and original RequestIdentity.
pub trait InstrumentStageRuntimeObservationPort: Send + Sync {
    /// Reports the P-04 child while it remains suspended. P-04 must not resume
    /// unless the authenticated echo response matches the request pins.
    fn before_resume(
        &self,
        identity: &RequestIdentity,
        request: InstrumentStageStartedRequest,
    ) -> Result<AuthenticatedKernelResponse, ProcessExecutionError>;

    /// Reports the actual executor's terminal view. The Kernel independently
    /// requires its retained native Job to be empty before releasing capacity.
    fn terminal(
        &self,
        identity: &RequestIdentity,
        request: InstrumentStageTerminalRequest,
    ) -> Result<AuthenticatedKernelResponse, ProcessExecutionError>;
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct KindKey {
    kind_id: String,
    kind_version: String,
}

#[derive(
    Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Clone, Debug, Eq, Ord, PartialEq, PartialOrd,
)]
struct OperationKey {
    operation_id: String,
    attempt_seq: Option<u32>,
}

#[cfg(windows)]
struct Reservation {
    identity: RequestIdentity,
    peer: PeerIdentity,
    intent: ProcessIntent,
    admission: InstrumentAdmissionGrant,
    dispatch_grant: Option<KernelDispatchGrant>,
    job_id: Option<String>,
    attempt_seq: Option<u32>,
    process_request_digest: Option<String>,
    job: Option<eliot_platform_windows::RecoverableJobObject>,
}

#[cfg(windows)]
#[derive(Default)]
struct RuntimeState {
    reservations: BTreeMap<OperationKey, Reservation>,
    used_attempts: BTreeSet<OperationKey>,
    latest_testd_attempt: BTreeMap<String, u32>,
    circuit_failures: BTreeMap<KindKey, u32>,
}

/// One process-lifetime shared owner on `KernelComposition`; all wrappers
/// contend for the same per-kind slots and retain their exact physical Job.
#[cfg(windows)]
#[derive(Default)]
pub struct InstrumentStageRuntime {
    state: Mutex<RuntimeState>,
}

#[cfg(windows)]
impl InstrumentStageRuntime {
    /// Creates the one empty Kernel-owned runtime state at composition build.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves one declared per-kind slot for the exact original stage before
    /// the Kernel response containing its dispatch grant can escape.
    pub fn reserve(
        &self,
        identity: &RequestIdentity,
        peer: &PeerIdentity,
        request: &InstrumentStageGrantRequest,
        admission: &InstrumentAdmissionGrant,
        dispatch_grant: &KernelDispatchGrant,
    ) -> Result<(), InstrumentStageRuntimeError> {
        if dispatch_grant.grant_digest.is_empty() {
            return Err(InstrumentStageRuntimeError::Binding);
        }
        self.reserve_original(
            identity,
            peer,
            &request.intent,
            Some(request),
            admission,
            Some(dispatch_grant.clone()),
            None,
            None,
            None,
        )
    }

    /// Reserves a durable TestD attempt from its original retained process
    /// intent/grant after the TestD owner has revalidated canonical currentness.
    /// The actual per-attempt P-03 digest is bound later from the executor's
    /// immutable request, never copied from the queued job's historical digest.
    pub fn reserve_testd_attempt(
        &self,
        identity: &RequestIdentity,
        peer: &PeerIdentity,
        job_id: &str,
        attempt_seq: u32,
        intent: &ProcessIntent,
        admission: &InstrumentAdmissionGrant,
        dispatch_grant: &KernelDispatchGrant,
    ) -> Result<(), InstrumentStageRuntimeError> {
        if job_id.is_empty() || attempt_seq == 0 || !valid_sha256(&dispatch_grant.grant_digest) {
            return Err(InstrumentStageRuntimeError::Binding);
        }
        self.reserve_original(
            identity,
            peer,
            intent,
            None,
            admission,
            Some(dispatch_grant.clone()),
            Some(job_id.to_owned()),
            Some(attempt_seq),
            None,
        )
    }

    /// Checks only whether a terminal carrier names an already-started exact
    /// owner reservation. This permits historical reconciliation through a
    /// newer session fence; `terminal` still validates the complete evidence
    /// and the retained Job before releasing anything.
    pub fn matches_terminal_binding(
        &self,
        identity: &RequestIdentity,
        peer: &PeerIdentity,
        request: &InstrumentStageTerminalRequest,
    ) -> bool {
        let Ok(()) = identity.validate() else {
            return false;
        };
        let Ok(()) = peer.validate() else {
            return false;
        };
        let key = operation_key(request.operation_id.as_str(), request.attempt_seq);
        let Ok(state) = self.state.lock() else {
            return false;
        };
        state.reservations.get(&key).is_some_and(|reservation| {
            reservation.job.is_some()
                && reservation.identity == *identity
                && reservation.peer == *peer
                && reservation.admission.grant_digest == request.admission_digest
                && reservation
                    .dispatch_grant
                    .as_ref()
                    .map(|grant| grant.grant_digest.as_str())
                    == request.dispatch_grant_digest.as_deref()
                && reservation.job_id == request.job_id
                && reservation.attempt_seq == request.attempt_seq
                && reservation.process_request_digest.as_deref()
                    == Some(request.process_request_digest.as_str())
        })
    }

    fn reserve_original(
        &self,
        identity: &RequestIdentity,
        peer: &PeerIdentity,
        intent: &ProcessIntent,
        request: Option<InstrumentStageGrantRequest>,
        admission: &InstrumentAdmissionGrant,
        dispatch_grant: Option<KernelDispatchGrant>,
        job_id: Option<String>,
        attempt_seq: Option<u32>,
        process_request_digest: Option<String>,
    ) -> Result<(), InstrumentStageRuntimeError> {
        identity
            .validate()
            .map_err(|_| InstrumentStageRuntimeError::Binding)?;
        peer.validate()
            .map_err(|_| InstrumentStageRuntimeError::Binding)?;
        intent
            .validate()
            .map_err(|_| InstrumentStageRuntimeError::Binding)?;
        if admission.grant_digest != admission.digest()
            || admission.max_concurrency == 0
            || admission.executable_file_identity.is_none()
            || intent.operation_id().as_str() != identity.request.metadata.request_id.as_str()
            || intent.instrument_admission_digest() != Some(admission.grant_digest.as_str())
            || intent.executable_file_identity() != admission.executable_file_identity.as_ref()
            || intent.executable() != admission.executable_path
            || intent.executable_sha256() != admission.content_digest
            || intent.argv() != admission.arguments
            || request
                .as_ref()
                .is_some_and(|request| request.validate_admission_binding(admission).is_err())
            || dispatch_grant.as_ref().is_some_and(|grant| {
                !valid_sha256(&grant.grant_digest)
                    || grant.authority_epoch != identity.request.state_fence.authority_epoch
                    || grant.fence_generation != intent.generation().get()
            })
            || !valid_source_binding(
                dispatch_grant.is_some(),
                job_id.is_some(),
                attempt_seq.is_some(),
                process_request_digest.is_some(),
            )
        {
            return Err(InstrumentStageRuntimeError::Binding);
        }
        let key = operation_key(intent.operation_id().as_str(), attempt_seq);
        let mut state = self
            .state
            .lock()
            .map_err(|_| InstrumentStageRuntimeError::Unavailable)?;
        let now_ms = unix_ms();
        if dispatch_grant
            .as_ref()
            .is_some_and(|grant| now_ms == 0 || grant.expires_at <= now_ms)
        {
            return Err(InstrumentStageRuntimeError::Binding);
        }
        // Expire only inert pending grants at the exact expiry carried by the
        // original Kernel grant. A started Job is never removed here.
        state.reservations.retain(|_, reservation| {
            reservation.job.is_some()
                || reservation
                    .dispatch_grant
                    .as_ref()
                    .is_none_or(|grant| grant.expires_at > now_ms)
        });
        if state.used_attempts.contains(&key)
            || attempt_seq.is_some_and(|attempt_seq| {
                state
                    .latest_testd_attempt
                    .get(&key.operation_id)
                    .is_some_and(|latest| attempt_seq <= *latest)
            })
            || state.reservations.values().any(|active| {
                active.intent.operation_id().as_str() == key.operation_id && active.job.is_some()
            })
        {
            return Err(InstrumentStageRuntimeError::Binding);
        }
        state.used_attempts.insert(key.clone());
        if let Some(attempt_seq) = attempt_seq {
            state
                .latest_testd_attempt
                .entry(key.operation_id.clone())
                .and_modify(|latest| *latest = (*latest).max(attempt_seq))
                .or_insert(attempt_seq);
        }
        state.reservations.insert(
            key,
            Reservation {
                identity: identity.clone(),
                peer: peer.clone(),
                intent: intent.clone(),
                admission: admission.clone(),
                dispatch_grant,
                job_id,
                attempt_seq,
                process_request_digest,
                job: None,
            },
        );
        Ok(())
    }

    /// Reopens and retains the exact suspended child's native Job before P-04
    /// resumes it. All identity pins come from the original reservation.
    pub fn started(
        &self,
        identity: &RequestIdentity,
        peer: &PeerIdentity,
        request: InstrumentStageStartedRequest,
    ) -> Result<InstrumentStageStartedResponse, InstrumentStageRuntimeError> {
        identity
            .validate()
            .map_err(|_| InstrumentStageRuntimeError::Binding)?;
        peer.validate()
            .map_err(|_| InstrumentStageRuntimeError::Binding)?;
        let operation = request.operation_id.as_str();
        let key = operation_key(operation, request.attempt_seq);
        let mut state = self
            .state
            .lock()
            .map_err(|_| InstrumentStageRuntimeError::Unavailable)?;
        let reservation = state
            .reservations
            .get(&key)
            .ok_or(InstrumentStageRuntimeError::Binding)?;
        let now_ms = unix_ms();
        if reservation.identity != *identity
            || reservation.peer != *peer
            || reservation.admission.grant_digest != request.admission_digest
            || reservation
                .dispatch_grant
                .as_ref()
                .map(|grant| grant.grant_digest.as_str())
                != request.dispatch_grant_digest.as_deref()
            || reservation
                .dispatch_grant
                .as_ref()
                .is_some_and(|grant| now_ms == 0 || grant.expires_at <= now_ms)
            || reservation.job_id != request.job_id
            || reservation.attempt_seq != request.attempt_seq
            || request.attempt_seq.is_some_and(|attempt_seq| {
                state.latest_testd_attempt.get(operation) != Some(&attempt_seq)
            })
            || !valid_sha256(&request.process_request_digest)
            || reservation.job.is_some()
            || reservation
                .process_request_digest
                .as_ref()
                .is_some_and(|digest| digest != &request.process_request_digest)
            || reservation.intent.executable_sha256()
                != request.suspended_identity.executable_sha256()
            || reservation.intent.executable() != request.launch.requested_executable()
            || request.suspended_identity.executable_sha256()
                != reservation.admission.content_digest
            || request.launch.requested_executable() != reservation.admission.executable_path
            || request.launch.executable_volume_serial_number()
                != reservation
                    .admission
                    .executable_file_identity
                    .ok_or(InstrumentStageRuntimeError::Binding)?
                    .volume_serial_number
            || request.launch.executable_file_index()
                != reservation
                    .admission
                    .executable_file_identity
                    .ok_or(InstrumentStageRuntimeError::Binding)?
                    .file_index
            || request
                .recoverable_job_binding
                .root()
                .executable_file_identity()
                != reservation
                    .admission
                    .executable_file_identity
                    .ok_or(InstrumentStageRuntimeError::Binding)?
        {
            return Err(InstrumentStageRuntimeError::Binding);
        }
        let kind = kind_key(&reservation.admission);
        let active_kind = state
            .reservations
            .values()
            .filter(|active| kind_key(&active.admission) == kind)
            .map(|active| (active.job.is_some(), active.admission.max_concurrency));
        if !capacity_available(reservation.admission.max_concurrency, active_kind) {
            return Err(InstrumentStageRuntimeError::Capacity);
        }
        let physical = request.suspended_identity.physical();
        let observed_root = request.recoverable_job_binding.root().process();
        let canonical_observed_image = std::fs::canonicalize(physical.image_path())
            .map_err(|_| InstrumentStageRuntimeError::Physical)?;
        if observed_root.process_id != physical.process_id()
            || observed_root.start_time_100ns != physical.start_time_100ns()
            || observed_root.image_path != physical.image_path()
            || !eliot_platform_windows::windows_paths_equal(
                &canonical_observed_image,
                std::path::Path::new(&reservation.admission.executable_path),
            )
            || request.recoverable_job_binding.job_identity().name() != physical.executor_job_name()
        {
            return Err(InstrumentStageRuntimeError::Binding);
        }
        let job =
            eliot_platform_windows::RecoverableJobObject::open(request.recoverable_job_binding)
                .map_err(|_| InstrumentStageRuntimeError::Physical)?;
        let peer_process = peer
            .process_binding()
            .ok_or(InstrumentStageRuntimeError::Binding)?;
        let expected_parent = eliot_platform_windows::ProcessIdentity {
            process_id: peer_process.process_id(),
            start_time_100ns: peer_process.start_time_100ns(),
            image_path: peer_process.image_path().to_owned(),
        };
        job.validate_root_parent(&expected_parent)
            .map_err(|_| InstrumentStageRuntimeError::Physical)?;
        let reservation = state
            .reservations
            .get_mut(&key)
            .ok_or(InstrumentStageRuntimeError::Binding)?;
        reservation.job = Some(job);
        reservation.process_request_digest = Some(request.process_request_digest.clone());
        Ok(InstrumentStageStartedResponse {
            operation_id: request.operation_id,
            admission_digest: request.admission_digest,
            dispatch_grant_digest: request.dispatch_grant_digest,
            attempt_seq: request.attempt_seq,
            job_id: request.job_id,
            process_request_digest: request.process_request_digest,
        })
    }

    /// Releases exactly one reservation only after its retained native Job is
    /// independently observed empty and terminal evidence matches the original
    /// P-04 operation. Semantic process failures do not count as circuit faults.
    pub fn terminal(
        &self,
        identity: &RequestIdentity,
        peer: &PeerIdentity,
        request: InstrumentStageTerminalRequest,
    ) -> Result<InstrumentStageTerminalResponse, InstrumentStageRuntimeError> {
        identity
            .validate()
            .map_err(|_| InstrumentStageRuntimeError::Binding)?;
        peer.validate()
            .map_err(|_| InstrumentStageRuntimeError::Binding)?;
        let operation = request.operation_id.as_str();
        let key = operation_key(operation, request.attempt_seq);
        let mut state = self
            .state
            .lock()
            .map_err(|_| InstrumentStageRuntimeError::Unavailable)?;
        let reservation = state
            .reservations
            .get(&key)
            .ok_or(InstrumentStageRuntimeError::Binding)?;
        request
            .evidence
            .validate()
            .map_err(|_| InstrumentStageRuntimeError::Binding)?;
        let view = request.evidence.view();
        let transport_failure = [request.evidence.stdout(), request.evidence.stderr()]
            .into_iter()
            .flatten()
            .any(|stream| stream.transport() == StreamTransportStatus::ReadFailed);
        if reservation.identity != *identity
            || reservation.peer != *peer
            || reservation.admission.grant_digest != request.admission_digest
            || reservation
                .dispatch_grant
                .as_ref()
                .map(|grant| grant.grant_digest.as_str())
                != request.dispatch_grant_digest.as_deref()
            || reservation.job_id != request.job_id
            || reservation.attempt_seq != request.attempt_seq
            || reservation.process_request_digest.as_deref()
                != Some(request.process_request_digest.as_str())
            || request.evidence.request_digest() != request.process_request_digest
            || view.operation_id().as_str() != operation
            || (!view.lifecycle().is_terminal()
                && view.lifecycle() != eliot_process::ProcessLifecycle::UnknownOutcome)
        {
            return Err(InstrumentStageRuntimeError::Binding);
        }
        let job = reservation
            .job
            .as_ref()
            .ok_or(InstrumentStageRuntimeError::Binding)?;
        let process_identity = view
            .identity()
            .ok_or(InstrumentStageRuntimeError::Binding)?;
        let process_physical = process_identity.physical();
        let job_root = job.binding().root();
        if process_physical.process_id() != job_root.process().process_id
            || process_physical.start_time_100ns() != job_root.process().start_time_100ns
            || process_physical.image_path() != job_root.process().image_path
            || process_physical.executor_job_name() != job.identity().name()
            || process_identity.executable_file_identity()
                != Some(&job_root.executable_file_identity())
        {
            return Err(InstrumentStageRuntimeError::Binding);
        }
        if job
            .active_process_count()
            .map_err(|_| InstrumentStageRuntimeError::Physical)?
            != 0
        {
            return Err(InstrumentStageRuntimeError::Physical);
        }
        let circuit_key = kind_key(&reservation.admission);
        let response = InstrumentStageTerminalResponse {
            operation_id: request.operation_id,
            admission_digest: request.admission_digest,
            dispatch_grant_digest: request.dispatch_grant_digest,
            attempt_seq: request.attempt_seq,
            job_id: request.job_id,
            process_request_digest: request.process_request_digest,
        };
        state.reservations.remove(&key);
        if transport_failure {
            let failures = state.circuit_failures.entry(circuit_key).or_default();
            *failures = failures.saturating_add(1);
        }
        Ok(response)
    }
}

#[cfg(windows)]
fn operation_key(operation_id: &str, attempt_seq: Option<u32>) -> OperationKey {
    OperationKey {
        operation_id: operation_id.to_owned(),
        attempt_seq,
    }
}

#[cfg(windows)]
fn valid_source_binding(
    has_dispatch_grant: bool,
    has_testd_job: bool,
    has_attempt_seq: bool,
    has_process_request_digest: bool,
) -> bool {
    (has_dispatch_grant && !has_testd_job && !has_attempt_seq && !has_process_request_digest)
        || (has_dispatch_grant && has_testd_job && has_attempt_seq && !has_process_request_digest)
}

#[cfg(windows)]
fn capacity_available(
    new_limit: u32,
    active_kind_reservations: impl Iterator<Item = (bool, u32)>,
) -> bool {
    let (occupied, effective_limit) = active_kind_reservations
        .filter(|(started, _)| *started)
        .fold(
            (0_usize, new_limit),
            |(count, limit), (_, original_limit)| {
                (count.saturating_add(1), limit.min(original_limit))
            },
        );
    occupied < effective_limit as usize
}

#[cfg(windows)]
fn kind_key(admission: &InstrumentAdmissionGrant) -> KindKey {
    KindKey {
        kind_id: admission.kind_id.clone(),
        kind_version: admission.kind_version.to_string(),
    }
}

#[cfg(windows)]
fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(windows)]
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(all(test, windows))]
mod tests {
    use super::{capacity_available, valid_source_binding};

    #[test]
    fn lifecycle_source_requires_one_closed_original_binding() {
        assert!(valid_source_binding(true, false, false, false));
        assert!(valid_source_binding(true, true, true, false));
        assert!(!valid_source_binding(true, true, true, true));
        assert!(!valid_source_binding(true, true, false, false));
        assert!(!valid_source_binding(false, false, true, false));
        assert!(!valid_source_binding(false, true, true, false));
    }

    #[test]
    fn started_slots_are_shared_across_wrappers_but_ignore_pending_other_kinds() {
        let active_kind_across_two_wrappers = [(true, 1), (true, 4), (false, 1)];
        assert!(!capacity_available(
            10,
            active_kind_across_two_wrappers.into_iter()
        ));
        let unrelated_kind_only = [(false, 1), (false, 1)];
        assert!(capacity_available(1, unrelated_kind_only.into_iter()));
        // A later registration with a higher limit cannot widen the older
        // live reservation's original ceiling.
        assert!(!capacity_available(10, [(true, 1)].into_iter()));
    }
}
