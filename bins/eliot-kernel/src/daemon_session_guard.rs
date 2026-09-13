//! Kernel daemon session guard.
//!
//! Fail-closed guard that binds the authenticated session to the current
//! daemon launch. Only the exact active `eliotd` caller is checked against
//! the live front-door policy; all other callers bypass this guard.
//!
//! Architecture: A12.2 Principal, Session и visibility; A12.3 Один governed write path; A13.2 Kernel и failure domains; ARCH-AUTH-01; ARCH-SEC-02
//! Implementation: I1.2 Обязательные процессы первого полного runtime; I7.3 Session lifecycle; I7.14 Session lifecycle; I15.2 Principal and Session binding
//! Forbidden authority: must not accept peer-owned identity, must not widen session scope, must not accept stale daemon caller.
//! Ordinary module: I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only `caller_binding`, `session_binding`, `retained_owner_epoch` and `KernelComposition::require_current_daemon_session` plus inseparable guard-only helpers with zero external users beyond the guard.

use eliot_contracts::EpochId;
use eliot_kernel_core::module::recovery_state_view::authority_epoch_id_from;

use super::runtime_identity::stable_owner_principal_digest;
use super::{
    ACTIVE_DAEMON_CALLER, Generation, KernelComposition, PeerIdentity, ProcessExecutionGateway,
    ProcessOwnerBinding, ProcessSessionBinding, Session, TransportError,
};

/// Resolves the retained process-authority epoch one session-bound owner must
/// carry (T2.md:177-206).
///
/// The full `EpochId` `(lineage_id, sequence)` pair comes from the gateway's
/// retained ORS snapshot lineage via the canonical `authority_epoch_id_from`:
/// a non-UUID lineage fails closed here instead of manufacturing one. The
/// caller passes the transport scalar it already proved (launch descriptor,
/// session handshake) as `expected_sequence`; drift between the retained
/// sequence and that scalar contour fails closed as well, so a stale contour
/// is never promoted into a binding.
pub(crate) fn retained_owner_epoch(
    gateway: &ProcessExecutionGateway,
    expected_sequence: u64,
) -> Result<EpochId, TransportError> {
    let epoch = authority_epoch_id_from(&gateway.snapshot_binding.authority_epoch().current)
        .map_err(|_| TransportError::SessionFenced)?;
    if epoch.sequence.get() != expected_sequence {
        return Err(TransportError::SessionFenced);
    }
    Ok(epoch)
}

pub(crate) fn session_binding(session: &Session) -> Result<ProcessSessionBinding, TransportError> {
    session
        .peer
        .validate()
        .map_err(|_| TransportError::PeerIdentityUnavailable)?;
    ProcessSessionBinding::new(&session.connection_id, session.session_epoch)
        .map_err(|_| TransportError::SessionFenced)
}

pub(crate) fn caller_binding(
    session: &Session,
    authority_epoch: &EpochId,
) -> Result<(ProcessOwnerBinding, ProcessSessionBinding), TransportError> {
    session
        .peer
        .validate()
        .map_err(|_| TransportError::PeerIdentityUnavailable)?;
    let generation = Generation::new(session.module_generation.generation.value())
        .map_err(|_| TransportError::SessionFenced)?;
    let stable_sid = match &session.peer {
        PeerIdentity::Authenticated { user_identity, .. } => user_identity,
        PeerIdentity::Unavailable { .. } => return Err(TransportError::PeerIdentityUnavailable),
    };
    let principal_digest = stable_owner_principal_digest(
        stable_sid,
        session.module_generation.module_id.as_str(),
        session.authority_epoch,
        generation,
    );
    let owner = ProcessOwnerBinding::new(
        session.module_generation.module_id.as_str(),
        principal_digest,
        authority_epoch.clone(),
        generation,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    let session_binding = session_binding(session)?;
    Ok((owner, session_binding))
}

impl KernelComposition {
    #[cfg(windows)]
    pub(crate) fn require_current_daemon_session(
        &self,
        session: &Session,
    ) -> Result<(), TransportError> {
        if session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Ok(());
        }
        let Some(launch) = self
            .active_daemon_launch()
            .map_err(|_| TransportError::SessionFenced)?
        else {
            return Ok(());
        };
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if session.accepts_bound(&policy.module_generation, launch.launch_nonce.as_str()) {
            Ok(())
        } else {
            Err(TransportError::SessionFenced)
        }
    }
}
