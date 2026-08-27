//! Kernel daemon session guard.
//!
//! Fail-closed guard that binds the authenticated session to the current
//! daemon launch. Only the exact active `eliotd` caller is checked against
//! the live front-door policy; all other callers bypass this guard.
//!
//! Architecture: A12.2 Principal, Session и visibility; A12.3 Один governed write path; A13.2 Kernel и failure domains; ARCH-AUTH-01; ARCH-SEC-02
//! Implementation: I1.2 Обязательные процессы первого полного runtime; I7.3 Session lifecycle; I7.14 Session lifecycle; I15.2 Principal and Session binding
//! Forbidden authority: must not accept peer-owned identity, must not widen session scope, must not accept stale daemon caller.
//! Ordinary module: I2.2 Когда capability становится отдельным crate; I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only `caller_binding` and `KernelComposition::require_current_daemon_session` plus inseparable guard-only helper with zero external users beyond the guard.

use super::runtime_identity::stable_owner_principal_digest;
use super::{
    ACTIVE_DAEMON_CALLER, Generation, KernelComposition, PeerIdentity, ProcessOwnerBinding,
    ProcessSessionBinding, Session, TransportError,
};

pub(crate) fn caller_binding(
    session: &Session,
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
        session.authority_epoch,
        generation,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    let session_binding = ProcessSessionBinding::new(&session.connection_id, session.session_epoch)
        .map_err(|_| TransportError::SessionFenced)?;
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
