//! Typed restore carrier for reactive runtime composition (I7.19, #1941/#1942).
//!
//! This module binds the exact closed request/reply shapes the live
//! `BridgeRunner` uses to restore its attach-scoped reactive state
//! (injection ledger + canonical resource snapshots) from canonical Store
//! projections through the Kernel front-door pipe. It mints nothing: the
//! ledger bytes stay owner-validated at restore, snapshot bytes stay
//! digest-bound at publish, and session/fence authority stays with the
//! admitted envelope plus the serving owners. The generic pipe carries the
//! bytes; this contract carries their meaning.

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Closed Kernel entry serving one reactive restore.
/// Mirrors the `agent_host_request_*` entry pattern: the literal names the
/// operation on the wire; the envelope carries authority.
pub const REACTIVE_RESTORE_OPERATION: &str = "agent_host_request_reactive_restore";
/// Envelope capability carried by restore requests. Names the operation
/// itself; it borrows no tool authority and admits no tool linkage.
pub const REACTIVE_RESTORE_CAPABILITY: &str = "agent_host_request_reactive_restore";
/// Exact payload-schema identity for the canonical restore query bytes.
pub const REACTIVE_RESTORE_PAYLOAD_SCHEMA_ID: &str = "eliot.bridge.reactive-restore.v1";
/// Stable identity of the reactive restore contract.
pub const REACTIVE_RESTORE_CONTRACT_NAME: &str = "eliot.foundation.reactive-restore";
/// Current semantic contract revision.
pub const REACTIVE_RESTORE_CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(1, 0, 0);
/// Maximum snapshot URIs carried by one restore query. Mirrors the
/// transport's per-item relation fan-out bound so one reply stays within
/// the ledger cap plus per-snapshot caps; the pipe frame limits fail closed
/// beyond that.
pub const MAX_RESTORE_URIS: usize = 8;
/// Maximum bytes for one bounded text field (session, URI).
pub const MAX_RESTORE_TEXT_BYTES: usize = 512;
/// Maximum bytes for one served ledger document. Mirrors the bridge ledger
/// codec ceiling (`MAX_LEDGER_JSON_BYTES`) so a durable ledger always fits;
/// shape authority stays with the ledger decoder at restore.
pub const MAX_RESTORE_LEDGER_BYTES: usize = 1024 * 1024;
/// Maximum bytes for one served snapshot. Mirrors the bridge resource
/// projection ceiling (`MAX_CONTENT_BYTES`); digest binding stays with
/// publish.
pub const MAX_RESTORE_SNAPSHOT_BYTES: usize = 1024 * 1024;

/// Errors returned by the pure reactive restore contract.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReactiveRestoreError {
    /// A field failed bounded identity validation.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable bounded reason.
        reason: &'static str,
    },
    /// A supplied value does not match the admitted binding it echoes.
    #[error("{field} does not match the admitted restore binding")]
    Mismatch {
        /// Field path that diverged.
        field: &'static str,
    },
    /// Canonical serialization failed.
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
}

fn bounded_text(value: &str, field: &'static str) -> Result<(), ReactiveRestoreError> {
    if value.trim().is_empty() {
        return Err(ReactiveRestoreError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ReactiveRestoreError::InvalidField {
            field,
            reason: "must be free of control characters",
        });
    }
    if value.len() > MAX_RESTORE_TEXT_BYTES {
        return Err(ReactiveRestoreError::InvalidField {
            field,
            reason: "exceeds the bounded text ceiling",
        });
    }
    Ok(())
}

/// Authenticated restore query: which session, under which fence, with which
/// snapshots. Session and fence are echoed from the live attach binding by
/// the caller; the serving side re-checks both against live authority and
/// refuses foreign values. URIs are caller-nominated candidates only:
/// canonical grammar and digest binding are enforced at publish, never here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveRestoreQuery {
    /// Live attach session the restore is evaluated for.
    pub session_id: String,
    /// Evaluation fence the restore is evaluated under.
    pub state_fence: StateFence,
    /// Bounded snapshot URI candidates to republish alongside the ledger.
    pub uris: Vec<String>,
}

impl ReactiveRestoreQuery {
    /// Validates shape only; authority stays with the admitted envelope plus
    /// the serving owners.
    pub fn validate(&self) -> Result<(), ReactiveRestoreError> {
        bounded_text(&self.session_id, "restore.session_id")?;
        self.state_fence
            .validate()
            .map_err(|_| ReactiveRestoreError::InvalidField {
                field: "restore.state_fence",
                reason: "fence has no identity-bearing dependency",
            })?;
        if self.uris.len() > MAX_RESTORE_URIS {
            return Err(ReactiveRestoreError::InvalidField {
                field: "restore.uris",
                reason: "exceeds the bounded URI fan-out",
            });
        }
        for uri in &self.uris {
            bounded_text(uri, "restore.uris.item")?;
        }
        Ok(())
    }

    /// Digest over the canonical query bytes for payload binding.
    pub fn canonical_digest(&self) -> Result<String, ReactiveRestoreError> {
        let bytes = canonical_json_bytes(self)
            .map_err(|error| ReactiveRestoreError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// One served snapshot: exact bytes for one URI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestoredSnapshot {
    /// Canonical `eliot://` resource identity served.
    pub uri: String,
    /// Exact snapshot bytes (digest-bound at publish).
    pub content: Vec<u8>,
}

/// Authenticated restore reply: session/fence echoes plus served bytes.
///
/// Absence is explicit: `ledger_json == None` means no durable ledger exists
/// for the session (restore proceeds empty); a URI absent from `snapshots`
/// was not served (not published). Errors fail the whole call instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveRestoreReply {
    /// Session the bytes were served for (must echo the query).
    pub session_id: String,
    /// Fence the bytes were served under (must echo the query).
    pub state_fence: StateFence,
    /// Verbatim canonical ledger snapshot, when durable state exists.
    pub ledger_json: Option<String>,
    /// Served snapshots in request order.
    pub snapshots: Vec<RestoredSnapshot>,
    /// Highest owner revision observed across served projections.
    pub revision: u64,
}

impl ReactiveRestoreReply {
    /// Validates reply shape (echo equality is checked by the caller
    /// against its live binding, never inside this helper).
    pub fn validate(&self) -> Result<(), ReactiveRestoreError> {
        bounded_text(&self.session_id, "restore_reply.session_id")?;
        self.state_fence
            .validate()
            .map_err(|_| ReactiveRestoreError::InvalidField {
                field: "restore_reply.state_fence",
                reason: "fence has no identity-bearing dependency",
            })?;
        if let Some(ledger) = &self.ledger_json
            && (ledger.is_empty() || ledger.len() > MAX_RESTORE_LEDGER_BYTES)
        {
            return Err(ReactiveRestoreError::InvalidField {
                field: "restore_reply.ledger_json",
                reason: "ledger document exceeds the bounded ledger ceiling",
            });
        }
        if self.snapshots.len() > MAX_RESTORE_URIS {
            return Err(ReactiveRestoreError::InvalidField {
                field: "restore_reply.snapshots",
                reason: "exceeds the bounded URI fan-out",
            });
        }
        for snapshot in &self.snapshots {
            bounded_text(&snapshot.uri, "restore_reply.snapshots.uri")?;
            if snapshot.content.len() > MAX_RESTORE_SNAPSHOT_BYTES {
                return Err(ReactiveRestoreError::InvalidField {
                    field: "restore_reply.snapshots.content",
                    reason: "snapshot exceeds the bounded content ceiling",
                });
            }
        }
        Ok(())
    }
}

/// Deterministic idempotency correlation for one restore query.
///
/// Binds session, epoch lineage/sequence, and generation so a repeated
/// identical query replays byte-identically (the Kernel deduplicates by
/// digest) while any binding change is a distinct operation.
#[must_use]
pub fn restore_correlation(session_id: &str, fence: &StateFence) -> String {
    format!(
        "reactive-restore:{}:{}:{}:{}",
        session_id,
        fence.authority_epoch.lineage_id.as_str(),
        fence.authority_epoch.sequence.get(),
        fence.resource_generation.value()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
                NonZeroU64::new(3).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(7).expect("generation"),
        )
    }

    fn query() -> ReactiveRestoreQuery {
        ReactiveRestoreQuery {
            session_id: "session-live-1".to_owned(),
            state_fence: test_fence(),
            uris: vec!["eliot://evidence/source-9".to_owned()],
        }
    }

    #[test]
    fn query_validates_and_digests_deterministically() {
        let first = query();
        first.validate().expect("valid query");
        let second = query();
        assert_eq!(
            first.canonical_digest().expect("digest"),
            second.canonical_digest().expect("digest")
        );
        let mut moved = query();
        moved.session_id = "session-other-2".to_owned();
        assert_ne!(
            first.canonical_digest().expect("digest"),
            moved.canonical_digest().expect("digest")
        );
    }

    #[test]
    fn query_rejects_blank_session_zero_fence_and_overbound_uris() {
        let mut blank = query();
        blank.session_id = "   ".to_owned();
        assert!(blank.validate().is_err());
        let mut zero = query();
        zero.state_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
                NonZeroU64::new(3).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::default(),
        );
        assert!(zero.validate().is_err());
        let mut many = query();
        many.uris = vec!["eliot://evidence/x".to_owned(); MAX_RESTORE_URIS + 1];
        assert!(many.validate().is_err());
    }

    #[test]
    fn reply_round_trips_and_rejects_unknown_fields() {
        let reply = ReactiveRestoreReply {
            session_id: "session-live-1".to_owned(),
            state_fence: test_fence(),
            ledger_json: Some("{\"contract\":\"eliot.agent-bridge.reactive-injection-receipts/v1\"}".to_owned()),
            snapshots: vec![RestoredSnapshot {
                uri: "eliot://evidence/source-9".to_owned(),
                content: vec![9, 9],
            }],
            revision: 4,
        };
        reply.validate().expect("valid reply");
        let bytes = serde_json::to_vec(&reply).expect("serializes");
        let back: ReactiveRestoreReply =
            serde_json::from_slice(&bytes).expect("deserializes");
        assert_eq!(reply, back);
        let mut hostile = serde_json::to_value(&reply).expect("value");
        hostile["shadow"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<ReactiveRestoreReply>(hostile).is_err());
    }

    #[test]
    fn correlation_binds_session_and_fence() {
        let base = restore_correlation("session-live-1", &test_fence());
        assert!(base.starts_with("reactive-restore:session-live-1:"));
        assert_ne!(base, restore_correlation("session-other-2", &test_fence()));
        let mut rotated = test_fence();
        rotated.resource_generation = ResourceGeneration::new(8).expect("generation");
        assert_ne!(base, restore_correlation("session-live-1", &rotated));
    }
}
