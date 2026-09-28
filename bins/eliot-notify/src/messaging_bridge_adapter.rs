//! Optional `MessagingBridge` attachment for the notify composition
//! (issue 1828, I10.23).
//!
//! The bridge is never constructed here on its own: the composition starts
//! without one, and the operator attaches an evidenced
//! [`MessagingBridge`](eliot_messaging_bridge::MessagingBridge) explicitly.
//! Absence leaves canonical delivery untouched, so enabling or disabling the
//! bridge cannot affect canonical message delivery. Claiming through the
//! attached bridge projects the existing committed outbox item and never
//! re-executes the work that produced it.

use eliot_messaging_bridge::{BridgeError, CommittedResult, DeliveryClaim, MessagingBridge};

use super::NotificationComposition;

impl NotificationComposition {
    /// Attaches an evidenced messaging bridge to the composition.
    pub fn attach_messaging_bridge(&mut self, bridge: MessagingBridge) {
        self.messaging_bridge = Some(bridge);
    }

    /// Detaches the messaging bridge; canonical delivery is unaffected.
    pub fn detach_messaging_bridge(&mut self) {
        self.messaging_bridge = None;
    }

    /// Returns the attached messaging bridge, if one is attached.
    pub fn messaging_bridge(&self) -> Option<&MessagingBridge> {
        self.messaging_bridge.as_ref()
    }

    /// Claims an existing committed outbox item through the attached bridge.
    ///
    /// Without an attached bridge this reports
    /// [`BridgeError::BridgeDisabled`] and performs no delivery projection,
    /// so the canonical path stays exactly as it was.
    pub fn claim_bridge_delivery(
        &self,
        committed: &CommittedResult,
    ) -> Result<DeliveryClaim, BridgeError> {
        match &self.messaging_bridge {
            Some(bridge) => bridge.claim_committed(committed),
            None => Err(BridgeError::BridgeDisabled),
        }
    }
}
