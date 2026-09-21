//! First production producer: settled plan output to bridge admission instructions.
//!
//! Converts one settled [`PendingContextInjectionPlan`] into exact
//! bridge-admission instructions for the agent-bridge delivery-record ledger.
//! This module performs the plan-side half of the I7.19 admit step: it selects
//! which planned items the bridge must admit, and binds each to its exact cue
//! source, firing evaluation, relations, scope, governance revision, and fence.
//! It performs no I/O, no delivery, no receipt issuance, and no persistence.
//!
//! Authority boundaries (see `../../control-20260921/1941-1942-runtime-owner-contracts.md`
//! contract C1 for the full transport picture):
//!
//! ```text
//! plan owns:   item selection, cue source/digest binding, firing-evaluation
//!              reference, relation handles, scope/governance/fence passthrough,
//!              severity (from owner-set stickiness), delivery channel
//!              (from per-item disposition), dedup keys, skip accounting.
//! bridge owns: session binding (live attach), ledger mutation, receipts,
//!              stickiness enforcement, normal dedup, representation checks.
//! governor owns (transport complement, NOT produced here): risk tier and any
//!              governance attestation beyond the policy digest.
//! ```
//!
//! Only first-delivery instructions are emitted. Items the bridge already holds
//! (`StickyPendingResolution`), already-closed attention (`Resolved`/`Waived`/
//! `Superseded`), withheld, stale, or omitted items are never re-emitted:
//! re-admitting them would fork duplicate ledger items the bridge must then
//! hold open. Counts of every skip class are reported so no drop is silent.

use eliot_context_contracts::AttentionResolution;
use eliot_contracts::{SessionId, StateFence};
use eliot_protocol::ReactiveContextContentRef;
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    DeliveryDisposition, PendingContextInjectionPlan, PlannedAttentionBinding, PlannedContextItem,
    PlannedItemKind,
};

/// Maximum relation handles carried on one instruction. Mirrors the bridge
/// ledger bound (`MAX_RELATION_ACTIVATIONS`); the producer enforces it at the
/// source so an over-bound plan fails here, never as a transport rejection.
pub const MAX_BRIDGE_RELATIONS: usize = 8;

/// Bridge admission severity derived from owner-set attention stickiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BridgeAdmissionSeverity {
    Critical,
    Normal,
}

/// Bridge delivery channel derived from the per-item plan disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BridgeAdmissionDelivery {
    HostHook,
    NextBridgeResponse,
}

/// One exact bridge-admission instruction for a single planned item.
///
/// Every text field is owner-derived and non-blank; the bridge records scope,
/// status, and governance strings verbatim (bounded-text validation only — it
/// performs no semantic interpretation). The risk tier is deliberately absent:
/// no plan source carries Governor risk, so the transport must supply it from
/// the risk owner before calling the bridge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeAdmissionInstruction {
    /// Plan-scoped opaque item identity; doubles as the cue identity.
    pub cue_id: String,
    /// Owner source identity (content contract name).
    pub cue_source: String,
    /// Owner revision of the source at observation time.
    pub cue_source_revision: String,
    /// Lowercase SHA-256 over the exact observed bytes.
    pub cue_digest: String,
    /// Exact firing-evaluation reference (`reactive-activation:<digest>`).
    pub rule_id: String,
    /// Bounded precomputed relation handles (activation targets).
    pub relations: Vec<String>,
    /// Owner scope text, recorded verbatim by the bridge.
    pub scope_id: String,
    /// Plan disposition text (`EVENT_PLAN` / `TOOL_ONLY_ADVISORY`).
    pub status: String,
    /// Policy digest as the governance revision reference.
    pub governance_profile_rev: String,
    /// Live fence carried natively (transport renders per bridge contract).
    pub fence: StateFence,
    /// Severity from owner-set attention stickiness.
    pub severity: BridgeAdmissionSeverity,
    /// Delivery channel from the per-item disposition.
    pub delivery: BridgeAdmissionDelivery,
    /// Stable replay key (`<plan result digest>:<item id>`).
    pub dedup_key: String,
    /// Native audit evidence (not bridge-consumed): plan item identity.
    pub plan_item_id: String,
    /// Native audit evidence: exact plan revision identity.
    pub plan_result_digest: String,
    /// Native audit evidence: the plan's stated firing reason.
    pub item_reason: String,
    /// Native audit evidence: the plan's attention binding, when present.
    pub attention: Option<PlannedAttentionBinding>,
}

/// One settled plan converted to bridge instructions plus honest skip counts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BridgeAdmissionBatch {
    /// Owner session; the transport MUST verify it equals the bridge's live
    /// attach session before calling — the bridge binds its own live session
    /// and never accepts session text as authority.
    pub session_id: SessionId,
    /// Owner scope for the whole batch.
    pub scope_id: WorkScopeId,
    /// Source-invalidation signals passed through for the bridge
    /// invalidation-aware dedup (`plan.invalidation` verbatim).
    pub invalidations: Vec<String>,
    /// First-delivery instructions, in plan order.
    pub items: Vec<BridgeAdmissionInstruction>,
    /// Already-delivered sticky items correctly not re-emitted.
    pub skipped_sticky: u64,
    /// Withheld/stale/omitted/closed items correctly not emitted.
    pub skipped_ineligible: u64,
}

/// Fail-closed producer errors. A malformed planned item aborts the batch so
/// a sourceless or over-bound instruction can never reach the transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeAdmissionError {
    /// A deliverable item carries no source reference to bind the cue to.
    MissingSource { item_id: String },
    /// A deliverable item exceeds the bridge relation bound.
    RelationBudgetExceeded { item_id: String, count: usize },
    /// An owner-derived text field is blank or otherwise unusable as-is.
    InvalidField { field: &'static str },
    /// An owner content reference fails its own validation.
    InvalidSourceContent { item_id: String, reason: String },
}

impl std::fmt::Display for BridgeAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSource { item_id } => {
                write!(
                    formatter,
                    "planned item {item_id} carries no source reference"
                )
            }
            Self::RelationBudgetExceeded { item_id, count } => {
                write!(
                    formatter,
                    "planned item {item_id} carries {count} relations over bound {MAX_BRIDGE_RELATIONS}"
                )
            }
            Self::InvalidField { field } => {
                write!(formatter, "{field} is blank or unusable")
            }
            Self::InvalidSourceContent { item_id, reason } => {
                write!(formatter, "planned item {item_id} source invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for BridgeAdmissionError {}

fn non_blank(value: &str, field: &'static str) -> Result<(), BridgeAdmissionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(BridgeAdmissionError::InvalidField { field });
    }
    Ok(())
}

/// Converts one settled pending plan into bridge admission instructions.
///
/// Emits exactly the items whose disposition routes to bridge delivery
/// (`EventPlan` → host hook, `ToolOnlyAdvisory` → next bridge response).
/// Omission items, already-delivered sticky items, terminally-resolved
/// attention, and every withheld/stale/ineligible disposition are skipped and
/// counted — never emitted, never silent.
pub fn plan_bridge_admissions(
    plan: &PendingContextInjectionPlan,
) -> Result<BridgeAdmissionBatch, BridgeAdmissionError> {
    non_blank(&plan.result_digest, "plan.result_digest")?;
    non_blank(&plan.activation_digest, "plan.activation_digest")?;
    non_blank(&plan.policy_digest, "plan.policy_digest")?;
    let mut batch = BridgeAdmissionBatch {
        session_id: plan.request.session_id.clone(),
        scope_id: plan.request.scope_id.clone(),
        invalidations: plan.invalidation.clone(),
        items: Vec::new(),
        skipped_sticky: 0,
        skipped_ineligible: 0,
    };
    for item in &plan.items {
        match map_item(plan, item)? {
            MappedItem::Emit(instruction) => batch.items.push(instruction),
            MappedItem::SkipSticky => batch.skipped_sticky += 1,
            MappedItem::SkipIneligible => batch.skipped_ineligible += 1,
        }
    }
    Ok(batch)
}

enum MappedItem {
    Emit(BridgeAdmissionInstruction),
    SkipSticky,
    SkipIneligible,
}

fn map_item(
    plan: &PendingContextInjectionPlan,
    item: &PlannedContextItem,
) -> Result<MappedItem, BridgeAdmissionError> {
    if item.kind == PlannedItemKind::Omission {
        return Ok(MappedItem::SkipIneligible);
    }
    if let Some(attention) = &item.attention {
        match attention.resolution {
            AttentionResolution::Resolved
            | AttentionResolution::Waived
            | AttentionResolution::Superseded => {
                return Ok(MappedItem::SkipIneligible);
            }
            AttentionResolution::Open | AttentionResolution::Unknown => {}
        }
    }
    let delivery = match item.disposition {
        DeliveryDisposition::EventPlan => BridgeAdmissionDelivery::HostHook,
        DeliveryDisposition::ToolOnlyAdvisory => BridgeAdmissionDelivery::NextBridgeResponse,
        DeliveryDisposition::StickyPendingResolution
        | DeliveryDisposition::DeliveredDuplicate
        | DeliveryDisposition::InFlight => {
            return Ok(MappedItem::SkipSticky);
        }
        _ => return Ok(MappedItem::SkipIneligible),
    };
    let status: &'static str = match item.disposition {
        DeliveryDisposition::EventPlan => "EVENT_PLAN",
        DeliveryDisposition::ToolOnlyAdvisory => "TOOL_ONLY_ADVISORY",
        _ => return Ok(MappedItem::SkipIneligible),
    };
    let source = item
        .source
        .first()
        .ok_or_else(|| BridgeAdmissionError::MissingSource {
            item_id: item.item_id.clone(),
        })?;
    validate_source(&item.item_id, source)?;
    if item.activation_targets.len() > MAX_BRIDGE_RELATIONS {
        return Err(BridgeAdmissionError::RelationBudgetExceeded {
            item_id: item.item_id.clone(),
            count: item.activation_targets.len(),
        });
    }
    let severity = match &item.attention {
        Some(attention) if attention.sticky => BridgeAdmissionSeverity::Critical,
        _ => BridgeAdmissionSeverity::Normal,
    };
    let mut relations = Vec::with_capacity(item.activation_targets.len());
    for target in &item.activation_targets {
        relations.push(target.as_str().to_owned());
    }
    non_blank(&item.item_id, "item.item_id")?;
    non_blank(&item.reason, "item.reason")?;
    Ok(MappedItem::Emit(BridgeAdmissionInstruction {
        cue_id: item.item_id.clone(),
        cue_source: source.contract.name.as_str().to_owned(),
        cue_source_revision: source.source_revision.clone(),
        cue_digest: source.content_sha256.clone(),
        rule_id: format!("reactive-activation:{}", plan.activation_digest),
        relations,
        scope_id: plan.request.scope_id.as_str().to_owned(),
        status: status.to_owned(),
        governance_profile_rev: plan.policy_digest.clone(),
        fence: plan.request.state_fence.clone(),
        severity,
        delivery,
        dedup_key: format!("{}:{}", plan.result_digest, item.item_id),
        plan_item_id: item.item_id.clone(),
        plan_result_digest: plan.result_digest.clone(),
        item_reason: item.reason.clone(),
        attention: item.attention.clone(),
    }))
}

fn validate_source(
    item_id: &str,
    source: &ReactiveContextContentRef,
) -> Result<(), BridgeAdmissionError> {
    source
        .validate()
        .map_err(|error| BridgeAdmissionError::InvalidSourceContent {
            item_id: item_id.to_owned(),
            reason: error.to_string(),
        })?;
    non_blank(source.contract.name.as_str(), "source.contract.name")?;
    Ok(())
}
