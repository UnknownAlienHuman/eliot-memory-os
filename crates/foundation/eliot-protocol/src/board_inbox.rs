//! Typed board-inbox read carrier for operator reads (I11.2/I11.5/I11.7, #1780).
//!
//! This module binds the exact closed request/reply shapes the operator
//! controlboard inbox path uses to read canonical notification state
//! through the Kernel front-door pipe. It mints nothing: the request
//! carries no caller parameters (the serving runtime reconciles the
//! fixed closed read on every request), the reply carries owner-produced
//! records/metrics/fence/revision, and session/fence authority stays with
//! the admitted frame plus the serving owner. The generic pipe carries
//! the bytes; this contract carries their meaning.
//!
//! Request (front-door `Request`/`Execute` frame payload):
//!
//! ```text
//! {"operation": "controlboard.inbox", "payload": {}}
//! ```
//!
//! Reply (`Response`/`Result` frame payload, correlated by connection and
//! request identity):
//!
//! ```text
//! {"status": "inbox", "service": <kernel service>, "protocol": <kernel protocol>,
//!  "read": {"records": [...], "metrics": {...}, "state_fence": {...}, "revision": N}}
//! ```
//!
//! The reply reuses the notify `ReadInbox` response envelope shape so one
//! operator consumer decodes both producers; `service`/`protocol` name the
//! actual producer and are correlation-only. Record, metric, fence, and
//! revision semantics stay owned by the canonical notification contract
//! (`eliot.notify.state.v1`); this module only names the front-door
//! operation carrying them.

use eliot_contracts::ContractVersion;

/// Closed Kernel entry serving one operator board-inbox read.
/// Mirrors the `agent_host_request_*` entry pattern: the literal names the
/// operation on the wire; the empty payload carries no caller parameters
/// because the serving runtime reconciles the fixed closed read
/// (all scopes, resolved records included, bounded page) on every request.
pub const BOARD_INBOX_OPERATION: &str = "controlboard.inbox";
/// Stable identity of the board-inbox read contract.
pub const BOARD_INBOX_CONTRACT_NAME: &str = "eliot.foundation.board-inbox";
/// Current semantic contract revision.
pub const BOARD_INBOX_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_and_contract_identities_are_exact() {
        assert_eq!(BOARD_INBOX_OPERATION, "controlboard.inbox");
        assert_eq!(BOARD_INBOX_CONTRACT_NAME, "eliot.foundation.board-inbox");
        assert_eq!(BOARD_INBOX_CONTRACT_VERSION, ContractVersion::new(1, 0, 0));
    }
}
