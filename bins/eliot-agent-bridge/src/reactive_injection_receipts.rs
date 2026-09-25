//! I7.19 reactive injection receipts for the agent bridge delivery face.
//!
//! This module owns the bridge-local persisted reactive-context pipeline
//! described by `docs/architecture/I07-19-reactive-context-sequence.md`:
//!
//! ```text
//! observed event -> normalize cues -> exact firing -> bounded relation
//! activation -> admission (scope/status/risk) -> pending injection ->
//! host hook or next bridge response -> Delivery/Injection Receipt ->
//! later influence/use/outcome update.
//! ```
//!
//! Critical items stay sticky in attention output until a durable
//! resolved, waived, or superseded disposition is recorded. Normal items
//! are session-deduplicated unless their source, revision, or risk
//! condition is invalidated. Absence of later use evidence is represented
//! as [`UseOutcome::Unknown`], never inferred.
//!
//! # Authority separation
//!
//! - **This module owns:** bridge-local delivery records only — pending
//!   injections, delivery/injection receipts, sticky-attention projection,
//!   and session deduplication. All state is `Serialize`/`Deserialize` so it
//!   can be persisted by the caller; this module performs no I/O, derives no
//!   session or authority from any transport, mints no identity beyond
//!   deterministic ledger counters, and grants nothing.
//! - **Callers supply:** explicit session/task/binding identifiers (including
//!   the Kernel-owned session binding), exact firing evidence, admission
//!   basis, and delivery points. Session and authority facts remain owned by
//!   their existing owners; per I7.7 nothing here is inferred from a
//!   connection or handshake.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Maximum bytes for one bounded text field.
pub const MAX_REACTIVE_TEXT_BYTES: usize = 8 * 1024;
/// Maximum canonical JSON bytes accepted when restoring a ledger.
pub const MAX_LEDGER_JSON_BYTES: usize = 1024 * 1024;
/// Maximum precomputed relations activated for one item.
pub const MAX_RELATION_ACTIVATIONS: usize = 8;
/// Maximum items retained in one ledger (pending plus delivered history).
pub const MAX_LEDGER_ITEMS: usize = 512;
/// Maximum pending (undelivered) injections held at once.
pub const MAX_PENDING_INJECTIONS: usize = 256;

/// Stable identity of this delivery-record contract.
pub const REACTIVE_INJECTION_CONTRACT: &str = "eliot.agent-bridge.reactive-injection-receipts/v1";

/// Closed error type for the reactive injection ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveInjectionError {
    /// A bounded text field is blank, carries control characters, or is oversized.
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// No exact firing rule evidence was supplied before relation activation.
    MissingFiringEvidence,
    /// Relation activation exceeds the bounded precomputed budget.
    RelationBudgetExceeded,
    /// Admission denied the item; the reason is recorded, not retried here.
    AdmissionDenied { reason: &'static str },
    /// A normal item for this session was already delivered and not invalidated.
    DuplicateSuppressed,
    /// The ledger or pending queue is at its bounded capacity.
    CapacityExceeded { what: &'static str },
    /// The referenced item does not exist in this ledger.
    UnknownItem,
    /// The transition is not allowed in the current item state.
    IllegalTransition { reason: &'static str },
    /// Restored or supplied bytes are outside the bounded representation.
    Representation { reason: &'static str },
}

impl fmt::Display for ReactiveInjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(f, "{field} is invalid: {reason}")
            }
            Self::MissingFiringEvidence => {
                write!(f, "exact firing evidence is required before activation")
            }
            Self::RelationBudgetExceeded => {
                write!(
                    f,
                    "relation activation exceeds {MAX_RELATION_ACTIVATIONS} bounded relations"
                )
            }
            Self::AdmissionDenied { reason } => write!(f, "admission denied: {reason}"),
            Self::DuplicateSuppressed => write!(
                f,
                "normal item already delivered in this session and not invalidated"
            ),
            Self::CapacityExceeded { what } => write!(f, "{what} exceeds bounded capacity"),
            Self::UnknownItem => write!(f, "unknown reactive item"),
            Self::IllegalTransition { reason } => write!(f, "illegal transition: {reason}"),
            Self::Representation { reason } => {
                write!(f, "ledger representation rejected: {reason}")
            }
        }
    }
}

impl std::error::Error for ReactiveInjectionError {}

fn bounded_text(value: &str, field: &'static str) -> Result<(), ReactiveInjectionError> {
    if value.trim().is_empty() {
        return Err(ReactiveInjectionError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ReactiveInjectionError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > MAX_REACTIVE_TEXT_BYTES {
        return Err(ReactiveInjectionError::InvalidField {
            field,
            reason: "exceeds bounded UTF-8 bytes",
        });
    }
    Ok(())
}

fn sha256_digest(value: &str, field: &'static str) -> Result<(), ReactiveInjectionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ReactiveInjectionError::InvalidField {
            field,
            reason: "must be lowercase SHA-256",
        });
    }
    Ok(())
}

/// Origin channel of a reactive cue: which observed world produced it.
///
/// Bridge-local injection vocabulary (`bins/eliot-agent-bridge` reactive
/// receipts only). This is a different vocabulary from both the frozen
/// legacy V1 kind enum and the A-10 current kind enum, so it carries an
/// owner-specific name that can never be read as either of them. Wire
/// spellings of the variants are unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CueOrigin {
    HostEvent,
    ToolObservation,
    TaskTransition,
}

/// One normalized host/tool/task cue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedCue {
    /// Stable cue identity minted by the cue owner.
    pub cue_id: String,
    /// Which observed world produced the cue.
    pub kind: CueOrigin,
    /// Owner source identity (feed, tool surface, or task owner).
    pub source: String,
    /// Owner revision of the source at observation time.
    pub source_revision: String,
    /// Canonical digest of the observed content.
    pub cue_digest: String,
}

impl NormalizedCue {
    fn validate(&self) -> Result<(), ReactiveInjectionError> {
        bounded_text(&self.cue_id, "cue.cue_id")?;
        bounded_text(&self.source, "cue.source")?;
        bounded_text(&self.source_revision, "cue.source_revision")?;
        sha256_digest(&self.cue_digest, "cue.cue_digest")?;
        Ok(())
    }
}

/// Exact firing evidence: which closed rule fired on which cue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiringEvidence {
    /// Exact firing rule identity (closed rule catalogue entry).
    pub rule_id: String,
    /// Cue this firing was evaluated against.
    pub cue_id: String,
    /// Cue digest the firing was evaluated against.
    pub cue_digest: String,
}

impl FiringEvidence {
    fn validate(&self) -> Result<(), ReactiveInjectionError> {
        bounded_text(&self.rule_id, "firing.rule_id")?;
        bounded_text(&self.cue_id, "firing.cue_id")?;
        sha256_digest(&self.cue_digest, "firing.cue_digest")?;
        Ok(())
    }
}

/// Item criticality. Only [`Severity::Critical`] items are sticky.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    Normal,
}

/// Assessed risk tier recorded at admission time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskTier {
    Low,
    Elevated,
    High,
    Severe,
}

/// Admission decision recorded against scope, status, risk,
/// GovernanceProfile revision, and State Fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionBasis {
    /// Scope the item was admitted under.
    pub scope_id: String,
    /// Status the item was admitted under.
    pub status: String,
    /// Risk tier assessed at admission.
    pub risk: RiskTier,
    /// GovernanceProfile revision consulted.
    pub governance_profile_rev: String,
    /// Authority epoch fencing the admission.
    pub fence_epoch: String,
    /// Resource generation fencing the admission (non-zero).
    pub fence_generation: u64,
    /// Whether the item was admitted, and at which severity.
    pub admitted_severity: Severity,
}

impl AdmissionBasis {
    fn validate(&self) -> Result<(), ReactiveInjectionError> {
        bounded_text(&self.scope_id, "admission.scope_id")?;
        bounded_text(&self.status, "admission.status")?;
        bounded_text(
            &self.governance_profile_rev,
            "admission.governance_profile_rev",
        )?;
        bounded_text(&self.fence_epoch, "admission.fence_epoch")?;
        if self.fence_generation == 0 {
            return Err(ReactiveInjectionError::InvalidField {
                field: "admission.fence_generation",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// Delivery point through which a pending injection reached the agent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum DeliveryPoint {
    /// Delivered through a host hook invocation.
    HostHook { hook_id: String },
    /// Delivered inside the next bridge response frame.
    NextBridgeResponse { response_id: String },
}

impl DeliveryPoint {
    fn validate(&self) -> Result<(), ReactiveInjectionError> {
        match self {
            Self::HostHook { hook_id } => bounded_text(hook_id, "delivery.hook_id"),
            Self::NextBridgeResponse { response_id } => {
                bounded_text(response_id, "delivery.response_id")
            }
        }
    }
}

/// Later observable use/influence/outcome. Absence of evidence stays
/// [`UseOutcome::Unknown`]; use is never inferred.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum UseOutcome {
    /// No observable use, influence, or outcome recorded yet.
    Unknown,
    /// The agent observably used the injected context.
    ObservedUse { detail: String },
    /// The injected context observably influenced work.
    ObservedInfluence { detail: String },
    /// A terminal outcome was observed for the injected context.
    Outcome { result: String },
}

impl UseOutcome {
    fn validate(&self) -> Result<(), ReactiveInjectionError> {
        match self {
            Self::Unknown => Ok(()),
            Self::ObservedUse { detail } => bounded_text(detail, "use.detail"),
            Self::ObservedInfluence { detail } => bounded_text(detail, "use.detail"),
            Self::Outcome { result } => bounded_text(result, "use.result"),
        }
    }
}

/// Durable terminal disposition. Only these clear critical stickiness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum ItemDisposition {
    /// Still open: critical items remain sticky.
    Open,
    /// Durably resolved by the owning disposition record.
    Resolved { record: String },
    /// Durably waived by the owning disposition record.
    Waived { record: String },
    /// Durably superseded by a newer item.
    Superseded { by_item: String },
}

impl ItemDisposition {
    fn validate(&self) -> Result<(), ReactiveInjectionError> {
        match self {
            Self::Open => Ok(()),
            Self::Resolved { record } | Self::Waived { record } => {
                bounded_text(record, "disposition.record")
            }
            Self::Superseded { by_item } => bounded_text(by_item, "disposition.by_item"),
        }
    }

    fn is_terminal(&self) -> bool {
        !matches!(self, Self::Open)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
enum ItemState {
    Pending,
    Delivered { receipt_seq: u64 },
}

/// One reactive item tracked from admission through disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReactiveItem {
    item_id: String,
    session_id: String,
    severity: Severity,
    cue: NormalizedCue,
    firing: FiringEvidence,
    relations: Vec<String>,
    admission: AdmissionBasis,
    state: ItemState,
    use_outcome: UseOutcome,
    disposition: ItemDisposition,
    invalidated: bool,
}

/// Delivery/Injection Receipt: proof that a pending injection reached the
/// agent through a recorded delivery point.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectionReceipt {
    /// Stable receipt identity minted from the ledger counter.
    pub receipt_id: String,
    /// Item this receipt delivers.
    pub item_id: String,
    /// Session the item was delivered into.
    pub session_id: String,
    /// Exact firing evidence behind the delivery.
    pub firing: FiringEvidence,
    /// Admission basis behind the delivery.
    pub admission: AdmissionBasis,
    /// Delivery point that carried the item.
    pub delivery: DeliveryPoint,
    /// Later use/influence/outcome status; [`UseOutcome::Unknown`] when none
    /// has been observed.
    pub use_status: UseOutcome,
}

/// One attention-projection row for a session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionItem {
    /// Item identity.
    pub item_id: String,
    /// Item severity.
    pub severity: Severity,
    /// Whether the item has been delivered at least once.
    pub delivered: bool,
    /// Receipt of the latest delivery, when delivered.
    pub receipt_id: Option<String>,
    /// Current durable disposition.
    pub disposition: ItemDisposition,
}

/// Persisted reactive-context pipeline: pending injections, delivery
/// receipts, sticky resolution state, and session deduplication.
///
/// The ledger is pure data: deterministic given the same call order, with no
/// I/O, clocks, or transport-derived identity. Persist by serializing with
/// [`ReactiveInjectionLedger::to_json_bytes`] and restoring with
/// [`ReactiveInjectionLedger::from_json_bytes`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactiveInjectionLedger {
    contract: Option<String>,
    next_item_seq: u64,
    next_receipt_seq: u64,
    items: BTreeMap<String, ReactiveItem>,
    receipts: BTreeMap<String, InjectionReceipt>,
}

impl ReactiveInjectionLedger {
    /// Create an empty ledger stamped with this delivery-record contract.
    #[must_use]
    pub fn new() -> Self {
        Self {
            contract: Some(REACTIVE_INJECTION_CONTRACT.to_owned()),
            next_item_seq: 0,
            next_receipt_seq: 0,
            items: BTreeMap::new(),
            receipts: BTreeMap::new(),
        }
    }

    /// Normalize a cue, check exact firing, activate a bounded relation set,
    /// and record the admission decision as one pending injection.
    ///
    /// Returns the minted item identity. A normal item for the same session,
    /// source, revision, and risk that is already delivered and not
    /// invalidated is rejected with
    /// [`ReactiveInjectionError::DuplicateSuppressed`].
    pub fn admit(
        &mut self,
        session_id: &str,
        cue: NormalizedCue,
        firing: Option<FiringEvidence>,
        relations: Vec<String>,
        admission: AdmissionBasis,
    ) -> Result<String, ReactiveInjectionError> {
        bounded_text(session_id, "session_id")?;
        cue.validate()?;
        let firing = firing.ok_or(ReactiveInjectionError::MissingFiringEvidence)?;
        firing.validate()?;
        if firing.cue_id != cue.cue_id || firing.cue_digest != cue.cue_digest {
            return Err(ReactiveInjectionError::InvalidField {
                field: "firing.cue",
                reason: "must bind the exact normalized cue",
            });
        }
        if relations.len() > MAX_RELATION_ACTIVATIONS {
            return Err(ReactiveInjectionError::RelationBudgetExceeded);
        }
        for relation in &relations {
            bounded_text(relation, "relations.item")?;
        }
        admission.validate()?;
        if self.items.len() >= MAX_LEDGER_ITEMS {
            return Err(ReactiveInjectionError::CapacityExceeded { what: "items" });
        }
        if self.pending_count() >= MAX_PENDING_INJECTIONS {
            return Err(ReactiveInjectionError::CapacityExceeded {
                what: "pending injections",
            });
        }
        if admission.admitted_severity == Severity::Normal
            && self.items.values().any(|item| {
                item.severity == Severity::Normal
                    && item.session_id == session_id
                    && item.cue.source == cue.source
                    && item.cue.source_revision == cue.source_revision
                    && item.admission.risk == admission.risk
                    && matches!(item.state, ItemState::Delivered { .. })
                    && !item.invalidated
            })
        {
            return Err(ReactiveInjectionError::DuplicateSuppressed);
        }
        self.next_item_seq += 1;
        let item_id = format!("reactive-item-{}", self.next_item_seq);
        self.items.insert(
            item_id.clone(),
            ReactiveItem {
                item_id: item_id.clone(),
                session_id: session_id.to_owned(),
                severity: admission.admitted_severity,
                cue,
                firing,
                relations,
                admission,
                state: ItemState::Pending,
                use_outcome: UseOutcome::Unknown,
                disposition: ItemDisposition::Open,
                invalidated: false,
            },
        );
        Ok(item_id)
    }

    /// Issue a Delivery/Injection Receipt by delivering a pending item
    /// through a host hook or the next bridge response.
    pub fn deliver(
        &mut self,
        item_id: &str,
        delivery: DeliveryPoint,
    ) -> Result<InjectionReceipt, ReactiveInjectionError> {
        delivery.validate()?;
        let item = self
            .items
            .get_mut(item_id)
            .ok_or(ReactiveInjectionError::UnknownItem)?;
        if item.disposition.is_terminal() {
            return Err(ReactiveInjectionError::IllegalTransition {
                reason: "item already carries a terminal disposition",
            });
        }
        match item.state {
            ItemState::Pending => {}
            ItemState::Delivered { .. } if item.invalidated => {}
            ItemState::Delivered { .. } => {
                return Err(ReactiveInjectionError::IllegalTransition {
                    reason: "item already delivered and not invalidated",
                });
            }
        }
        self.next_receipt_seq += 1;
        let receipt_id = format!("injection-receipt-{}", self.next_receipt_seq);
        let receipt = InjectionReceipt {
            receipt_id: receipt_id.clone(),
            item_id: item.item_id.clone(),
            session_id: item.session_id.clone(),
            firing: item.firing.clone(),
            admission: item.admission.clone(),
            delivery,
            use_status: item.use_outcome.clone(),
        };
        item.state = ItemState::Delivered {
            receipt_seq: self.next_receipt_seq,
        };
        item.invalidated = false;
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    /// Record a later observable use, influence, or outcome update for a
    /// delivered item. Items with no update keep [`UseOutcome::Unknown`].
    pub fn record_use(
        &mut self,
        item_id: &str,
        update: UseOutcome,
    ) -> Result<(), ReactiveInjectionError> {
        update.validate()?;
        if matches!(update, UseOutcome::Unknown) {
            return Err(ReactiveInjectionError::IllegalTransition {
                reason: "unknown is the absence of an update, not an update",
            });
        }
        let item = self
            .items
            .get_mut(item_id)
            .ok_or(ReactiveInjectionError::UnknownItem)?;
        if !matches!(item.state, ItemState::Delivered { .. }) {
            return Err(ReactiveInjectionError::IllegalTransition {
                reason: "use can only be observed after delivery",
            });
        }
        item.use_outcome = update.clone();
        if let ItemState::Delivered { receipt_seq } = item.state {
            let receipt_id = format!("injection-receipt-{receipt_seq}");
            if let Some(receipt) = self.receipts.get_mut(&receipt_id) {
                receipt.use_status = update;
            }
        }
        Ok(())
    }

    /// Record a durable resolved, waived, or superseded disposition. Only a
    /// terminal disposition clears critical stickiness.
    pub fn record_disposition(
        &mut self,
        item_id: &str,
        disposition: ItemDisposition,
    ) -> Result<(), ReactiveInjectionError> {
        disposition.validate()?;
        if !disposition.is_terminal() {
            return Err(ReactiveInjectionError::IllegalTransition {
                reason: "only a terminal disposition changes resolution state",
            });
        }
        let item = self
            .items
            .get_mut(item_id)
            .ok_or(ReactiveInjectionError::UnknownItem)?;
        if let ItemDisposition::Superseded { by_item } = &disposition {
            if by_item == item_id {
                return Err(ReactiveInjectionError::IllegalTransition {
                    reason: "an item cannot supersede itself",
                });
            }
        }
        item.disposition = disposition;
        Ok(())
    }

    /// Invalidate session deduplication for a source whose revision or risk
    /// condition changed. Delivered normal items from that source become
    /// eligible for re-admission; critical stickiness is unaffected.
    pub fn invalidate_source(&mut self, source: &str) -> usize {
        let mut count = 0;
        for item in self.items.values_mut() {
            if item.cue.source == source && matches!(item.state, ItemState::Delivered { .. }) {
                item.invalidated = true;
                count += 1;
            }
        }
        count
    }

    /// Project the attention output for a session: every open critical item
    /// (pending or delivered — sticky until a terminal disposition), plus
    /// pending normal items. Delivered normals appear only after
    /// invalidation re-admits and re-delivers them as new items.
    #[must_use]
    pub fn attention_output(&self, session_id: &str) -> Vec<AttentionItem> {
        let mut output = Vec::new();
        for item in self.items.values() {
            if item.session_id != session_id || item.disposition.is_terminal() {
                continue;
            }
            let delivered = matches!(item.state, ItemState::Delivered { .. });
            if item.severity == Severity::Normal && delivered && !item.invalidated {
                continue;
            }
            let receipt_id = match item.state {
                ItemState::Delivered { receipt_seq } => {
                    Some(format!("injection-receipt-{receipt_seq}"))
                }
                ItemState::Pending => None,
            };
            output.push(AttentionItem {
                item_id: item.item_id.clone(),
                severity: item.severity,
                delivered,
                receipt_id,
                disposition: item.disposition.clone(),
            });
        }
        output
    }

    /// Look up a receipt by identity.
    #[must_use]
    pub fn receipt(&self, receipt_id: &str) -> Option<&InjectionReceipt> {
        self.receipts.get(receipt_id)
    }

    /// Returns the ledger session bound to one item identity, if the item
    /// exists.
    ///
    /// Read-only probe for the observer-handle join: resolution succeeds
    /// only for exact ledger identities, never by pattern or inference.
    /// Covers every retained item regardless of attention visibility.
    #[must_use]
    pub fn item_session(&self, item_id: &str) -> Option<&str> {
        self.items.get(item_id).map(|item| item.session_id.as_str())
    }

    /// Bounded identities of pending (undelivered) injections for one
    /// session in ledger order.
    ///
    /// The delivery owner drains this list at a real delivery boundary (a
    /// host hook invocation or the next bridge response) and issues one
    /// [`InjectionReceipt`] per item via [`Self::deliver`]. At most
    /// [`MAX_PENDING_INJECTIONS`] identities are ever returned.
    #[must_use]
    pub fn pending_item_ids(&self, session_id: &str) -> Vec<String> {
        self.items
            .values()
            .filter(|item| {
                item.session_id == session_id && matches!(item.state, ItemState::Pending)
            })
            .map(|item| item.item_id.clone())
            .collect()
    }

    /// Number of pending (undelivered) injections.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.items
            .values()
            .filter(|item| matches!(item.state, ItemState::Pending))
            .count()
    }

    /// Serialize the ledger to bounded canonical JSON for persistence.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ReactiveInjectionError> {
        let bytes =
            serde_json::to_vec(self).map_err(|_| ReactiveInjectionError::Representation {
                reason: "serialization failed",
            })?;
        if bytes.len() > MAX_LEDGER_JSON_BYTES {
            return Err(ReactiveInjectionError::CapacityExceeded { what: "ledger" });
        }
        Ok(bytes)
    }

    /// Restore a ledger from bounded JSON produced by
    /// [`ReactiveInjectionLedger::to_json_bytes`].
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ReactiveInjectionError> {
        if bytes.is_empty() || bytes.len() > MAX_LEDGER_JSON_BYTES {
            return Err(ReactiveInjectionError::Representation {
                reason: "outside bounded wire length",
            });
        }
        let ledger: Self =
            serde_json::from_slice(bytes).map_err(|_| ReactiveInjectionError::Representation {
                reason: "decode failed",
            })?;
        if ledger.contract.as_deref() != Some(REACTIVE_INJECTION_CONTRACT) {
            return Err(ReactiveInjectionError::Representation {
                reason: "wrong reactive injection contract",
            });
        }
        Ok(ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CUE_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn cue(source_revision: &str) -> NormalizedCue {
        NormalizedCue {
            cue_id: "cue-1".to_owned(),
            kind: CueOrigin::ToolObservation,
            source: "tool-surface".to_owned(),
            source_revision: source_revision.to_owned(),
            cue_digest: CUE_DIGEST.to_owned(),
        }
    }

    fn firing() -> FiringEvidence {
        FiringEvidence {
            rule_id: "exact-rule-7".to_owned(),
            cue_id: "cue-1".to_owned(),
            cue_digest: CUE_DIGEST.to_owned(),
        }
    }

    fn admission(severity: Severity, risk: RiskTier) -> AdmissionBasis {
        AdmissionBasis {
            scope_id: "scope-1".to_owned(),
            status: "active".to_owned(),
            risk,
            governance_profile_rev: "gov-3".to_owned(),
            fence_epoch: "epoch-1".to_owned(),
            fence_generation: 2,
            admitted_severity: severity,
        }
    }

    fn attention_ids(ledger: &ReactiveInjectionLedger, session: &str) -> Vec<String> {
        ledger
            .attention_output(session)
            .iter()
            .map(|item| item.item_id.clone())
            .collect()
    }

    #[test]
    fn critical_stays_sticky_until_durably_resolved() {
        let mut ledger = ReactiveInjectionLedger::new();
        let item = ledger
            .admit(
                "session-1",
                cue("rev-1"),
                Some(firing()),
                vec!["rel-a".to_owned()],
                admission(Severity::Critical, RiskTier::Severe),
            )
            .expect("admit critical");
        let receipt = ledger
            .deliver(
                &item,
                DeliveryPoint::NextBridgeResponse {
                    response_id: "resp-1".to_owned(),
                },
            )
            .expect("deliver critical");
        assert_eq!(receipt.use_status, UseOutcome::Unknown);
        // Later attention output still carries the critical item.
        assert!(attention_ids(&ledger, "session-1").contains(&item));
        assert!(attention_ids(&ledger, "session-1").contains(&item));
        // Observable use does not clear stickiness.
        ledger
            .record_use(
                &item,
                UseOutcome::ObservedInfluence {
                    detail: "shaped retry".to_owned(),
                },
            )
            .expect("record use");
        assert!(attention_ids(&ledger, "session-1").contains(&item));
        // Only a durable terminal disposition clears it.
        ledger
            .record_disposition(
                &item,
                ItemDisposition::Resolved {
                    record: "owner-fix-9".to_owned(),
                },
            )
            .expect("resolve");
        assert!(!attention_ids(&ledger, "session-1").contains(&item));
    }

    #[test]
    fn normal_session_item_deduplicated_until_invalidated() {
        let mut ledger = ReactiveInjectionLedger::new();
        let first = ledger
            .admit(
                "session-1",
                cue("rev-1"),
                Some(firing()),
                vec!["rel-a".to_owned()],
                admission(Severity::Normal, RiskTier::Low),
            )
            .expect("admit normal");
        ledger
            .deliver(
                &first,
                DeliveryPoint::HostHook {
                    hook_id: "hook-1".to_owned(),
                },
            )
            .expect("deliver normal");
        // Delivered normals leave attention output and are not re-admitted.
        assert!(!attention_ids(&ledger, "session-1").contains(&first));
        assert!(matches!(
            ledger.admit(
                "session-1",
                cue("rev-1"),
                Some(firing()),
                vec!["rel-a".to_owned()],
                admission(Severity::Normal, RiskTier::Low),
            ),
            Err(ReactiveInjectionError::DuplicateSuppressed)
        ));
        // A source/revision/risk change invalidates the deduplication.
        assert_eq!(ledger.invalidate_source("tool-surface"), 1);
        let second = ledger
            .admit(
                "session-1",
                cue("rev-2"),
                Some(firing()),
                vec!["rel-a".to_owned()],
                admission(Severity::Normal, RiskTier::Low),
            )
            .expect("re-admit after invalidation");
        assert_ne!(first, second);
        let receipt = ledger
            .deliver(
                &second,
                DeliveryPoint::HostHook {
                    hook_id: "hook-2".to_owned(),
                },
            )
            .expect("deliver after invalidation");
        assert_ne!(
            receipt.receipt_id,
            format!("injection-receipt-{}", 1),
            "second delivery mints a distinct receipt"
        );
    }

    #[test]
    fn receipt_identifies_firing_admission_delivery_and_outcome() {
        let mut ledger = ReactiveInjectionLedger::new();
        let item = ledger
            .admit(
                "session-1",
                cue("rev-1"),
                Some(firing()),
                vec!["rel-a".to_owned(), "rel-b".to_owned()],
                admission(Severity::Critical, RiskTier::High),
            )
            .expect("admit");
        let delivery = DeliveryPoint::HostHook {
            hook_id: "hook-9".to_owned(),
        };
        let receipt = ledger.deliver(&item, delivery).expect("deliver");
        assert_eq!(receipt.firing.rule_id, "exact-rule-7");
        assert_eq!(receipt.firing.cue_digest, CUE_DIGEST);
        assert_eq!(receipt.admission.scope_id, "scope-1");
        assert_eq!(receipt.admission.risk, RiskTier::High);
        assert_eq!(receipt.admission.fence_generation, 2);
        assert!(matches!(receipt.delivery, DeliveryPoint::HostHook { .. }));
        assert_eq!(receipt.use_status, UseOutcome::Unknown);
        ledger
            .record_use(
                &item,
                UseOutcome::Outcome {
                    result: "task-green".to_owned(),
                },
            )
            .expect("record outcome");
        let stored = ledger
            .receipt(&receipt.receipt_id)
            .expect("receipt retained");
        assert!(matches!(stored.use_status, UseOutcome::Outcome { .. }));
        // The ledger round-trips through its persisted representation.
        let bytes = ledger.to_json_bytes().expect("serialize ledger");
        let restored = ReactiveInjectionLedger::from_json_bytes(&bytes).expect("restore ledger");
        assert_eq!(restored, ledger);
    }

    #[test]
    fn pending_item_ids_lists_only_undelivered_session_items() {
        let mut ledger = ReactiveInjectionLedger::new();
        let critical = ledger
            .admit(
                "session-1",
                cue("rev-1"),
                Some(firing()),
                vec!["rel-a".to_owned()],
                admission(Severity::Critical, RiskTier::Severe),
            )
            .expect("admit critical");
        let normal = ledger
            .admit(
                "session-1",
                cue("rev-1"),
                Some(firing()),
                Vec::new(),
                admission(Severity::Normal, RiskTier::Low),
            )
            .expect("admit normal");
        let other_session = ledger
            .admit(
                "session-2",
                cue("rev-1"),
                Some(firing()),
                Vec::new(),
                admission(Severity::Normal, RiskTier::Low),
            )
            .expect("admit other session");
        assert_eq!(
            ledger.pending_item_ids("session-1"),
            vec![critical.clone(), normal.clone()]
        );
        assert_eq!(ledger.pending_item_ids("session-2"), vec![other_session]);
        assert!(ledger.pending_item_ids("session-9").is_empty());
        ledger
            .deliver(
                &normal,
                DeliveryPoint::NextBridgeResponse {
                    response_id: "resp-1".to_owned(),
                },
            )
            .expect("deliver normal");
        // Delivered items leave the pending drain; the critical item stays.
        assert_eq!(ledger.pending_item_ids("session-1"), vec![critical]);
    }
}
