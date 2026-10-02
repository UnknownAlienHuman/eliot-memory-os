//! Activation-graph derived report/projection data-model cell — decoded graph-row transport only.
//! Architecture A13.2 (Kernel and failure domains): minimal live Kernel preserves canonical history, fencing, health and recovery entrypoint and does not depend on model/Dreamer/graph/provider/UI; this cell owns no canonical state, authority, or write path.
//! Implementation I16.1 (Four surfaces): operational logs, metrics, durable audit, and reports — reports are Human/agent projections generated from canonical state ("prose not truth"); this cell is the I16.1 report/projection truth-boundary handle for UL activation graph rows (`CoChange` plus Card/Capsule/Concept/Support/Verified edges). Reports/projections are not truth/authority; they are derived, rebuildable, and must not confer canonical write authority.
//! Mechanical extraction from `crates/eliot-store/src/canonical_store.rs` — preserves exact behavior, public API, imports, serde shape, and `CanonicalStore` facade. No semantic redesign and no canonical write-authority change. Excludes provider/handshake/migration/atomic-write, capacity/L2/recall, and Dreamer/Luna semantics.

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawActivationRelation {
    pub(super) from_ref: String,
    pub(super) to_ref: String,
}

/// Decoder: derived struct, no `flatten`. Unknown member keys are refused.
/// Every family key is required: the `LoadUlActivationGraph` projection
/// always emits all seven keys (an empty family arrives as `[]`), so an
/// absent family is a partial transport and must be refused rather than
/// read as a known-empty graph.
/// Boundary: this decoder runs on an already-normalized `serde_json::Value`
/// (`decode_value` is `serde_json::from_value`), so these attributes prove
/// refusal of unknown and absent members of that projection only. Lexical
/// duplicate keys in the original response bytes are collapsed by the raw
/// parse in `surreal_rpc.rs::parse_response`; duplicate-sensitive validation
/// of the original bytes belongs to that transport ingress owner.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawActivationGraphRows {
    pub(super) co_change: Vec<eliot_types::CoChangeEdge>,
    pub(super) card_covers: Vec<RawActivationRelation>,
    pub(super) capsule_covers: Vec<RawActivationRelation>,
    pub(super) concept_implemented_by: Vec<RawActivationRelation>,
    pub(super) concept_depends_on: Vec<RawActivationRelation>,
    pub(super) supports: Vec<RawActivationRelation>,
    pub(super) verified_by: Vec<RawActivationRelation>,
}
