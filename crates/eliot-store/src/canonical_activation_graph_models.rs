//! Activation-graph derived report/projection data-model cell — decoded graph-row transport only.
//! Architecture A13.2 (Kernel and failure domains): minimal live Kernel preserves canonical history, fencing, health and recovery entrypoint and does not depend on model/Dreamer/graph/provider/UI; this cell owns no canonical state, authority, or write path.
//! Implementation I16.1 (Four surfaces): operational logs, metrics, durable audit, and reports — reports are Human/agent projections generated from canonical state ("prose not truth"); this cell is the I16.1 report/projection truth-boundary handle for UL activation graph rows (`CoChange` plus Card/Capsule/Concept/Support/Verified edges). Reports/projections are not truth/authority; they are derived, rebuildable, and must not confer canonical write authority.
//! Mechanical extraction from `crates/eliot-store/src/canonical_store.rs` — preserves exact behavior, public API, imports, serde shape, and `CanonicalStore` facade. No semantic redesign and no canonical write-authority change. Excludes provider/handshake/migration/atomic-write, capacity/L2/recall, and Dreamer/Luna semantics.

#[derive(serde::Deserialize)]
pub(super) struct RawActivationRelation {
    pub(super) from_ref: String,
    pub(super) to_ref: String,
}

#[derive(serde::Deserialize)]
pub(super) struct RawActivationGraphRows {
    #[serde(default)]
    pub(super) co_change: Vec<eliot_types::CoChangeEdge>,
    #[serde(default)]
    pub(super) card_covers: Vec<RawActivationRelation>,
    #[serde(default)]
    pub(super) capsule_covers: Vec<RawActivationRelation>,
    #[serde(default)]
    pub(super) concept_implemented_by: Vec<RawActivationRelation>,
    #[serde(default)]
    pub(super) concept_depends_on: Vec<RawActivationRelation>,
    #[serde(default)]
    pub(super) supports: Vec<RawActivationRelation>,
    #[serde(default)]
    pub(super) verified_by: Vec<RawActivationRelation>,
}
