//! Kernel daemon session guard.
//!
//! Fail-closed guard that binds the authenticated session to the current
//! daemon launch. Only the exact active `eliotd` caller is checked against
//! the live front-door policy; all other callers bypass this guard.
//!
//! Architecture: A12.2 Principal, Session и visibility; A12.3 Один governed write path; A13.2 Kernel и failure domains; ARCH-AUTH-01; ARCH-SEC-02
//! Implementation: I1.2 Обязательные процессы первого полного runtime; I7.3 Session lifecycle; I7.14 Session lifecycle; I15.2 Principal and Session binding
//! Forbidden authority: must not accept peer-owned identity, must not widen session scope, must not accept stale daemon caller.
//! Ordinary module: I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only `caller_binding` and `KernelComposition::require_current_daemon_session` plus inseparable guard-only helper with zero external users beyond the guard.

use super::front_door_session::{DOCTOR_MODULE_ID, NATIVE_MODULE_ID, TESTD_MODULE_ID};
use super::runtime_identity::stable_owner_principal_digest;
use super::{
    ACTIVE_DAEMON_CALLER, Generation, KernelComposition, PeerIdentity, ProcessCallerSession,
    ProcessOwnerBinding, ProcessSessionBinding, ProcessSessionClass, ProcessTransportRebindReceipt,
    Session, SessionId, TransportError,
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
        // INTENDED EpochId shape (B→A→C): session.authority_epoch is EpochId
        // after B cutover; clone via is_same_authority threading.
        &session.authority_epoch,
        generation,
    );
    let owner = ProcessOwnerBinding::new(
        session.module_generation.module_id.as_str(),
        principal_digest,
        session.authority_epoch.clone(),
        generation,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    let session_binding = ProcessSessionBinding::new(&session.connection_id, session.session_epoch)
        .map_err(|_| TransportError::SessionFenced)?;
    Ok((owner, session_binding))
}

/// Maps an authenticated module identity to its durable process session
/// class (issue #79).
///
/// The class is assigned from the server-admitted module identity, never from
/// wire content. Service modules with an exact server-side contour binding
/// (`eliotd`, `eliot-testd`, `eliot-native-worker`) resolve to their own
/// class; every other authenticated module (interactive User Broker and
/// future broker-class callers) resolves to the broker session class. The
/// one-shot Doctor module has no durable process-session contour on this
/// base, so it admits nothing here and stays fail-closed at the seams.
pub(crate) fn process_session_class_for_module(module_id: &str) -> Option<ProcessSessionClass> {
    if module_id == ACTIVE_DAEMON_CALLER {
        Some(ProcessSessionClass::EliotdGeneration)
    } else if module_id == TESTD_MODULE_ID {
        Some(ProcessSessionClass::TestdAttempt)
    } else if module_id == NATIVE_MODULE_ID {
        Some(ProcessSessionClass::NativeWorkerAttempt)
    } else if module_id == DOCTOR_MODULE_ID {
        None
    } else {
        Some(ProcessSessionClass::UserBrokerSession)
    }
}

/// Derives the canonical durable session identity for a non-daemon class.
///
/// Inputs are reconnect-stable authenticated values only: the assigned class,
/// the server-admitted module, the authenticated peer SID and peer session,
/// and the module generation. The transport `connection_id`, transport
/// session epoch, and authority epoch are deliberately excluded: reconnect
/// must preserve the session, and an epoch change must surface as a stale
/// epoch failure (not a silently different session) at validation time. The
/// domain-separated digest is one-way; no session value is ever parsed back
/// into a connection.
pub(crate) fn durable_caller_session_id(
    class: ProcessSessionClass,
    module_id: &str,
    peer_sid: &str,
    peer_session: &str,
    generation: Generation,
) -> Result<eliot_process::SessionId, TransportError> {
    if module_id.trim().is_empty() || peer_sid.trim().is_empty() || peer_session.trim().is_empty() {
        return Err(TransportError::SessionFenced);
    }
    let material = serde_json::json!({
        "domain": "eliot-process-caller-session/v1",
        "class": class.as_str(),
        "module_id": module_id,
        "peer_sid": peer_sid,
        "peer_session": peer_session,
        "generation": generation.get(),
    });
    let bytes = serde_json::to_vec(&material).map_err(|_| TransportError::SessionFenced)?;
    SessionId::new(super::sha256_hex(&bytes)).map_err(|_| TransportError::SessionFenced)
}

impl KernelComposition {
    /// Resolves the durable admitted process-caller session for an
    /// authenticated transport session (issue #79).
    ///
    /// The returned binding carries the exact owner plus the exact durable
    /// session under its typed class. Every input is server-admitted state:
    /// the stable owner comes from [`caller_binding`], the class from the
    /// admitted module identity, and the session identity from the active
    /// daemon launch (service-owned class) or from reconnect-stable
    /// authenticated peer/module values (all other classes). The transport
    /// `connection_id` enters only the separate ephemeral
    /// [`ProcessSessionBinding`]; it is never promoted into this binding, so
    /// two pipes for one principal resolve to one durable session with two
    /// distinct ephemeral bindings.
    pub(crate) fn admitted_process_caller_session(
        &self,
        session: &Session,
    ) -> Result<ProcessCallerSession, TransportError> {
        let (owner, _) = caller_binding(session)?;
        let (peer_sid, peer_session) = match &session.peer {
            PeerIdentity::Authenticated {
                user_identity,
                session_identity,
                ..
            } => (user_identity.as_str(), session_identity.as_str()),
            PeerIdentity::Unavailable { .. } => {
                return Err(TransportError::PeerIdentityUnavailable);
            }
        };
        let module_id = session.module_generation.module_id.as_str();
        let class =
            process_session_class_for_module(module_id).ok_or(TransportError::SessionFenced)?;
        let session_id = match class {
            ProcessSessionClass::EliotdGeneration => self.admitted_eliotd_session_id()?,
            ProcessSessionClass::UserBrokerSession
            | ProcessSessionClass::TestdAttempt
            | ProcessSessionClass::NativeWorkerAttempt => durable_caller_session_id(
                class,
                module_id,
                peer_sid,
                peer_session,
                owner.generation(),
            )?,
        };
        ProcessCallerSession::new(class, owner, session_id)
            .map_err(|_| TransportError::SessionFenced)
    }

    /// Recomputes the service-owned daemon session identity from the live
    /// active launch (issue #79).
    ///
    /// This is the exact mint the approved `eliotd` launch contour uses for
    /// its intent session, recomputed here from server-retained state (active
    /// launch descriptor plus live observation of the Kernel's own process)
    /// rather than trusted from the wire. Without an active launch there is
    /// no admitted daemon session and Start stays fenced.
    #[cfg(windows)]
    fn admitted_eliotd_session_id(&self) -> Result<SessionId, TransportError> {
        let launch = self
            .active_daemon_launch()
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        let kernel_process = super::observe_named_pipe_peer_process(std::process::id())
            .map_err(|_| TransportError::SessionFenced)?;
        let attempt = super::eliotd_launch_attempt_identity(
            &launch,
            kernel_process.process_id(),
            kernel_process.start_time_100ns(),
            kernel_process.image_path(),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let short = attempt.get(..16).ok_or(TransportError::SessionFenced)?;
        SessionId::new(format!("eliotd-session-{short}")).map_err(|_| TransportError::SessionFenced)
    }

    /// Service-owned launch contour is Windows-only on this base; without it
    /// no daemon session can be admitted.
    #[cfg(not(windows))]
    fn admitted_eliotd_session_id(&self) -> Result<SessionId, TransportError> {
        Err(TransportError::SessionFenced)
    }

    /// Mints the explicit transport-rebind receipt for a reconnect that keeps
    /// the admitted durable caller session (issue #79, I7.14–I7.15).
    ///
    /// Resolves the durable caller (unchanged across reconnect) and binds the
    /// freshly established `(connection_id, session_epoch)` to it without
    /// rewriting the intent or effect digest. Fencing the superseded
    /// transport remains the front-door's duty.
    ///
    /// This remains Kernel-private until the front-door reconnect contour
    /// wires it; the session-identity tests exercise it as the explicit
    /// rebind seam meanwhile.
    #[allow(dead_code)]
    pub(crate) fn rebind_process_transport(
        &self,
        session: &Session,
    ) -> Result<ProcessTransportRebindReceipt, TransportError> {
        let caller = self.admitted_process_caller_session(session)?;
        ProcessTransportRebindReceipt::mint(&caller, &session.connection_id, session.session_epoch)
            .map_err(|_| TransportError::SessionFenced)
    }
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
