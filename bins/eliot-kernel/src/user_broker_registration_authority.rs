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
    RegistrationRequest,
};

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
}

/// The Kernel-owned current registration table. It is deliberately not a
/// recovery cache: process restart starts empty and any active opaque ORS row
/// then fails closed until a separately authorized recovery path exists.
#[derive(Default)]
pub(crate) struct UserBrokerRegistrationAuthority {
    pub(crate) live: Mutex<BTreeMap<String, LiveUserBrokerRegistration>>,
    pub(crate) fenced_replays: Mutex<BTreeMap<String, UserBrokerFenceReplay>>,
}
