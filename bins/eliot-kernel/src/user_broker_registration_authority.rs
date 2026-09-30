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
use eliot_ors::{OperationIdentity, UserBrokerRegistrationReceipt};
use eliot_protocol::{ProtocolVersion, RequestIdentity};
use eliot_user_broker_core::{RegistrationGrant, RegistrationReceipt, RegistrationRequest};

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
}

/// The Kernel-owned current registration table. It is deliberately not a
/// recovery cache: process restart starts empty and any active opaque ORS row
/// then fails closed until a separately authorized recovery path exists.
#[derive(Default)]
pub(crate) struct UserBrokerRegistrationAuthority {
    pub(crate) live: Mutex<BTreeMap<String, LiveUserBrokerRegistration>>,
}
