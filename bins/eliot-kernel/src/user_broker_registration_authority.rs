//! Live, process-local User Broker registration authority.
//!
//! ORS intentionally persists the registration payload as an opaque record.
//! This cell is the only place that retains the typed registration issued to
//! one admitted transport session; a row loaded from ORS is never decoded into
//! live authority.

use std::collections::BTreeMap;
use std::sync::Mutex;

use eliot_contracts::{EpochId, StateFence};
use eliot_ipc::{PeerIdentity, Session};
use eliot_ors::{OperationIdentity, OperationalRecordInput, UserBrokerRegistrationReceipt};
use eliot_protocol::{ProtocolVersion, RequestIdentity};
use eliot_user_broker_core::{
    RegistrationFenceReceipt, RegistrationFenceRequest, RegistrationGrant, RegistrationReceipt,
    RegistrationRequest, RegistrationStatus,
};

use super::TransportError;

/// One exact authenticated transport binding retained with a registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UserBrokerSessionBinding {
    connection_id: String,
    protocol_version: ProtocolVersion,
    peer: PeerIdentity,
    authority_epoch: EpochId,
    module_generation: eliot_runtime_contracts::ModuleGeneration,
    launch_nonce: String,
    session_epoch: u64,
}

impl UserBrokerSessionBinding {
    /// Captures the fields that identify this admitted session, excluding its
    /// mutable open/fenced lifecycle bit.
    pub(crate) fn capture(session: &Session) -> Self {
        Self {
            connection_id: session.connection_id.clone(),
            protocol_version: session.protocol_version,
            peer: session.peer.clone(),
            authority_epoch: session.authority_epoch.clone(),
            module_generation: session.module_generation.clone(),
            launch_nonce: session.launch_nonce.clone(),
            session_epoch: session.session_epoch,
        }
    }

    pub(crate) fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub(crate) const fn session_epoch(&self) -> u64 {
        self.session_epoch
    }

    /// Returns whether a dispatch still belongs to the exact captured
    /// authenticated session.
    pub(crate) fn matches(&self, session: &Session) -> bool {
        self.connection_id == session.connection_id
            && self.protocol_version == session.protocol_version
            && self.peer == session.peer
            && self.authority_epoch == session.authority_epoch
            && self.module_generation == session.module_generation
            && self.launch_nonce == session.launch_nonce
            && self.session_epoch == session.session_epoch
    }
}

/// One admitted User Broker operation identity retained for cross-operation
/// reuse detection (issue #74 W7; I5.5 identity-conflict rule).
///
/// The entry binds the spent request id, cancellation id, and idempotency key
/// to the exact operation and canonical digest they were admitted for. A
/// later presentation of the same idempotency key must name the same
/// operation and digest (an exact-retry candidate the per-operation handler
/// then confirms); any other use of a spent identity is a typed identity
/// conflict. Entries live and die with their registration cell: a fenced or
/// dropped registration carries its spent evidence into its fence replay or
/// disappears with the dead session, and a new registration starts a new
/// chain. An expired deadline is never permission to forget a spent identity
/// while its registration cell lives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpentUserBrokerOperationIdentity {
    pub(crate) operation: String,
    pub(crate) request_id: String,
    pub(crate) idempotency_key: String,
    pub(crate) cancellation_id: String,
    pub(crate) canonical_digest: String,
}

/// The exact typed registration returned by Kernel for one live connection.
#[derive(Clone, Debug)]
pub(crate) struct LiveUserBrokerRegistration {
    pub(crate) session: UserBrokerSessionBinding,
    pub(crate) registration: RegistrationRequest,
    pub(crate) grant: RegistrationGrant,
    pub(crate) receipt: RegistrationReceipt,
    pub(crate) request_identity: RequestIdentity,
    pub(crate) subject_id: OperationIdentity,
    pub(crate) authority_epoch: EpochId,
    pub(crate) state_fence: StateFence,
    pub(crate) store_receipt: UserBrokerRegistrationReceipt,
    pub(crate) store_operation_order: u64,
    pub(crate) store_record: OperationalRecordInput,
    pub(crate) last_observed_at: u64,
    pub(crate) heartbeat_replay: Option<UserBrokerHeartbeatReplay>,
    pub(crate) spent: Vec<SpentUserBrokerOperationIdentity>,
}

/// The exact last heartbeat revision may be replayed only while it still
/// names the current active registration snapshot.
#[derive(Clone, Debug)]
pub(crate) struct UserBrokerHeartbeatReplay {
    pub(crate) registration: RegistrationReceipt,
    pub(crate) observed_at: u64,
    pub(crate) identity: RequestIdentity,
    pub(crate) grant: RegistrationGrant,
}

/// Terminal response evidence for one exact explicit fence retry. This row
/// holds no live authority and is removed when its transport session ends.
/// It carries the spent operation identities of its dead registration so a
/// retried fence under a reused key is still judged against the exact bytes
/// that key was admitted for.
#[derive(Clone, Debug)]
pub(crate) struct UserBrokerFenceReplay {
    pub(crate) session: UserBrokerSessionBinding,
    pub(crate) registration: RegistrationRequest,
    pub(crate) request: RegistrationFenceRequest,
    pub(crate) identity: RequestIdentity,
    pub(crate) receipt: RegistrationFenceReceipt,
    pub(crate) subject_id: OperationIdentity,
    pub(crate) store_receipt: UserBrokerRegistrationReceipt,
    pub(crate) store_operation_order: u64,
    pub(crate) store_record: OperationalRecordInput,
    pub(crate) spent: Vec<SpentUserBrokerOperationIdentity>,
}

/// I1.6 WorkScope execution identity bound to one broker registration.
///
/// A broker registration is inherently user-session-bound: the only WorkScope
/// it can ever authorize is `interactive_user:<sid>` for the exact SID it was
/// admitted for. `service` and `remote` scopes are never derived from a broker
/// registration here; they are admitted (or refused) on their own owner
/// paths, never through this cell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BrokerWorkScope {
    InteractiveUser { sid: String },
}

impl BrokerWorkScope {
    /// Derives the single WorkScope identity one registration authorizes.
    pub(crate) fn for_registration(registration: &RegistrationRequest) -> Self {
        Self::InteractiveUser {
            sid: registration.windows_sid.clone(),
        }
    }

    /// Projects the scope to its I1.6 route string (`interactive_user:<sid>`).
    pub(crate) fn route_string(&self) -> String {
        match self {
            Self::InteractiveUser { sid } => format!("interactive_user:{sid}"),
        }
    }
}

/// Admits one `interactive_user:<sid>` scoped execution against the exact
/// live registration that authorizes it (issue #1889 AC1).
///
/// The claimed scope must equal the WorkScope identity derived from the live
/// registration, the presenting receipt must still name that same
/// SID/session tuple with an Active status, and both the receipt and the
/// registration lease must be unexpired at `now`. Anything else fails closed
/// with [`TransportError::SessionFenced`]: a scope mismatch is presented
/// evidence that does not match, never a reason to fence a live registration.
pub(crate) fn admit_interactive_user_execution(
    registration: &RegistrationRequest,
    receipt: &RegistrationReceipt,
    scope: &str,
    now: u64,
) -> Result<BrokerWorkScope, TransportError> {
    let expected = BrokerWorkScope::for_registration(registration);
    if scope != expected.route_string()
        || receipt.status != RegistrationStatus::Active
        || receipt.windows_sid != registration.windows_sid
        || receipt.interactive_session_id != registration.interactive_session_id
        || receipt.registration_digest.trim().is_empty()
        || now >= receipt.expires_at
        || now >= registration.lease_expires_at
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(expected)
}

/// The Kernel-owned current registration table. It is deliberately not a
/// recovery cache: process restart starts empty and any active opaque ORS row
/// then fails closed until a separately authorized recovery path exists.
#[derive(Default)]
pub(crate) struct UserBrokerRegistrationAuthority {
    pub(crate) live: Mutex<BTreeMap<String, LiveUserBrokerRegistration>>,
    pub(crate) fenced_replays: Mutex<BTreeMap<String, UserBrokerFenceReplay>>,
}
