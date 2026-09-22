//! D2 live-ledger owner publication: session + attention from the live ledger.
//!
//! Position in the I7.19 sequence (`docs/architecture/I07-19-reactive-context-sequence.md`):
//!
//! ```text
//! pending injection -> host hook or next bridge response
//! -> Delivery/Injection Receipt -> attention output (this module publishes it live)
//! ```
//!
//! This module owns nothing but the observation: it reads the live
//! [`BridgeRunner`](super::BridgeRunner) ledger through the existing
//! in-tree observation surface and republishes it bound to the exact live
//! attach session and fence. It mints no session, no fence, no receipt, no
//! disposition, and no digest.
//!
//! # Authority separation
//!
//! - **This module owns:** one causal read of the live ledger per call
//!   ([`publish_live_ledger_session`], [`publish_live_ledger_attention`]).
//!   It holds no state across calls.
//! - **Bridge owns (never produced here):** the live attach session/fence
//!   binding, ledger mutation, receipts, stickiness enforcement, normal
//!   dedup. Observed through `BridgeRunner::attach_view`,
//!   `BridgeRunner::reactive_attention` (`bins/eliot-agent-bridge/src/lib.rs`),
//!   and `ReactiveInjectionLedger::attention_output`
//!   (`bins/eliot-agent-bridge/src/reactive_injection_receipts.rs`).
//! - **Session/attention owners own (never produced here):** the
//!   owner-issued `SessionDeliverySnapshot` / `CriticalAttentionProjection`
//!   contract projections. The companion bind module
//!   (`crates/smart/eliot-reactive-context-plan/src/coverage_policy_owner_bind.rs`)
//!   validates those projections with their in-tree validated constructors
//!   and requires their `session_id` / `state_fence` to equal the live
//!   [`LiveLedgerSession::session_id`] / [`LiveLedgerSession::fence`]
//!   published here. Session and authority facts are never inferred from
//!   deserialize-success, a URI, or a provided string.
//!
//! # Stickiness honesty
//!
//! Critical items stay sticky in [`LiveLedgerAttention::open_critical`]
//! until the ledger records a durable resolved, waived, or superseded
//! disposition: the ledger's `attention_output` already excludes only
//! terminal-disposition items
//! (`bins/eliot-agent-bridge/src/reactive_injection_receipts.rs`, `attention_output`),
//! and this module clones that set unchanged — it never re-adds a terminal
//! item and never infers resolution. Delivered normal items stay absent
//! until invalidation re-admits them, exactly as the ledger projects.
//! Absence of later use evidence stays unknown on the receipt
//! (`UseOutcome::Unknown`); use is never inferred here.
//!
//! # Registration
//!
//! This file is wired by the manager (manifests/registrations are
//! manager-owned). Required line in `bins/eliot-agent-bridge/src/lib.rs`:
//!
//! ```text
//! pub mod reactive_owner_publication;
//! ```

use eliot_agent_bridge_core::BridgeError;
use eliot_contracts::{ResourceGeneration, StateFence};

use super::BridgeRunner;
use super::reactive_injection_receipts::{AttentionItem, Severity};

/// Fail-closed publication errors. The ledger owns the reason detail; this
/// module owns only the transport-facing classification, mirroring
/// `reactive_ledger_error` in `bins/eliot-agent-bridge/src/lib.rs`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerPublicationError {
    /// No live attach: there is no session or fence to publish under.
    NotAttached,
    /// The live attach fence carries a zero generation and cannot key a
    /// publication.
    InvalidFence,
}

impl core::fmt::Display for OwnerPublicationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAttached => write!(formatter, "no live attach session to publish under"),
            Self::InvalidFence => {
                write!(formatter, "live attach fence generation must be non-zero")
            }
        }
    }
}

impl std::error::Error for OwnerPublicationError {}

impl OwnerPublicationError {
    /// Project onto the closed bridge error set without inventing a variant.
    #[must_use]
    pub fn to_bridge_error(&self) -> BridgeError {
        match self {
            Self::NotAttached => BridgeError::NotAttached,
            Self::InvalidFence => BridgeError::InvalidContract {
                field: "attach.state_fence.generation",
                reason: "generation must be non-zero",
            },
        }
    }
}

/// Live fence echoed from the attach binding, exactly as
/// `live_state_fence` does in
/// `bins/eliot-agent-bridge/src/reactive_runtime_composition.rs`:
/// epoch clone plus generation value; authority stays with the binding.
fn live_state_fence(runner: &BridgeRunner) -> Result<(String, StateFence), OwnerPublicationError> {
    let view = runner
        .attach_view()
        .ok_or(OwnerPublicationError::NotAttached)?;
    let binding = view.binding();
    let session_id = binding.session_id().as_str().to_owned();
    let generation = ResourceGeneration::new(binding.state_fence().generation().get())
        .map_err(|_| OwnerPublicationError::InvalidFence)?;
    let fence = StateFence::new(binding.state_fence().authority_epoch().clone(), generation);
    Ok((session_id, fence))
}

/// Live-ledger session publication: the exact live session/fence plus the
/// ledger's honest open set for that session.
///
/// - `pending_item_ids`: open items not yet delivered (`delivered == false`
///   in `BridgeRunner::reactive_attention`).
/// - `open_delivered_receipt_ids`: open items already delivered, by receipt
///   identity (`receipt_id` on delivered attention rows). Delivered normal
///   items that the ledger deduplicated are honestly absent here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveLedgerSession {
    /// Exact live attach session the ledger was read under.
    pub session_id: String,
    /// Exact live attach fence the ledger was read under.
    pub fence: StateFence,
    /// Open undelivered item identities in ledger order.
    pub pending_item_ids: Vec<String>,
    /// Receipt identities of open delivered items in ledger order.
    pub open_delivered_receipt_ids: Vec<String>,
}

/// Live-ledger attention publication: the sticky-critical set plus pending
/// normals, cloned unchanged from `BridgeRunner::reactive_attention`.
///
/// Every open critical item stays present (pending or delivered) until the
/// ledger records a durable resolved, waived, or superseded disposition;
/// delivered normals appear only after invalidation re-admits them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveLedgerAttention {
    /// Exact live attach session the attention was read under.
    pub session_id: String,
    /// Exact live attach fence the attention was read under.
    pub fence: StateFence,
    /// Open critical items, sticky until a terminal disposition.
    pub open_critical: Vec<AttentionItem>,
    /// Pending (undelivered) normal item identities in ledger order.
    pub pending_normal_ids: Vec<String>,
}

/// Publish the live-ledger session observation under the exact live
/// session/fence. Fails closed while detached.
pub fn publish_live_ledger_session(
    runner: &BridgeRunner,
) -> Result<LiveLedgerSession, OwnerPublicationError> {
    let (session_id, fence) = live_state_fence(runner)?;
    let attention = runner.reactive_attention();
    let mut pending_item_ids = Vec::new();
    let mut open_delivered_receipt_ids = Vec::new();
    for item in &attention {
        if item.delivered {
            if let Some(receipt_id) = item.receipt_id.clone() {
                open_delivered_receipt_ids.push(receipt_id);
            }
        } else {
            pending_item_ids.push(item.item_id.clone());
        }
    }
    Ok(LiveLedgerSession {
        session_id,
        fence,
        pending_item_ids,
        open_delivered_receipt_ids,
    })
}

/// Publish the live-ledger attention observation under the exact live
/// session/fence. Fails closed while detached. The critical set is the
/// ledger's own sticky projection, cloned without filtering.
pub fn publish_live_ledger_attention(
    runner: &BridgeRunner,
) -> Result<LiveLedgerAttention, OwnerPublicationError> {
    let (session_id, fence) = live_state_fence(runner)?;
    let attention = runner.reactive_attention();
    let mut open_critical = Vec::new();
    let mut pending_normal_ids = Vec::new();
    for item in attention {
        match item.severity {
            Severity::Critical => open_critical.push(item),
            Severity::Normal => {
                if !item.delivered {
                    pending_normal_ids.push(item.item_id.clone());
                }
            }
        }
    }
    Ok(LiveLedgerAttention {
        session_id,
        fence,
        open_critical,
        pending_normal_ids,
    })
}
