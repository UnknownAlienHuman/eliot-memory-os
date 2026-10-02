//! Activation-graph derived report/projection data-model cell — decoded graph-row transport only.
//! Architecture A13.2 (Kernel and failure domains): minimal live Kernel preserves canonical history, fencing, health and recovery entrypoint and does not depend on model/Dreamer/graph/provider/UI; this cell owns no canonical state, authority, or write path.
//! Implementation I16.1 (Four surfaces): operational logs, metrics, durable audit, and reports — reports are Human/agent projections generated from canonical state ("prose not truth"); this cell is the I16.1 report/projection truth-boundary handle for UL activation graph rows (`CoChange` plus Card/Capsule/Concept/Support/Verified edges). Reports/projections are not truth/authority; they are derived, rebuildable, and must not confer canonical write authority.
//! Mechanical extraction from `crates/eliot-store/src/canonical_store.rs` — preserves exact behavior, public API, imports, serde shape, and `CanonicalStore` facade. No semantic redesign and no canonical write-authority change. Excludes provider/handshake/migration/atomic-write, capacity/L2/recall, and Dreamer/Luna semantics.
//!
//! Transport decode boundary (#940). These two records — not the public
//! projection — are the real decoder on the production activation path:
//!
//! ```text
//! eliot_engine::ul::activation::ActivationEngine::activate
//! → CanonicalStore::load_ul_activation_graph
//! → execute_value(LoadUlActivationGraph)
//! → decode_value::<RawActivationGraphRows>   (serde_json::from_value)
//! → eliot_types::UlActivationGraphRows
//! ```
//!
//! The closed public type is constructed only after this decode, so it cannot
//! reject anything already erased here. Absence of evidence is not evidence of
//! an empty graph: a family may not be defaulted away, and no member may be
//! dropped silently.

/// Transport decoder for one projected relation row: derived struct, no
/// `flatten`, no tag, no `alias`. Unknown member keys are refused
/// (`deny_unknown_fields`); duplicate member keys are already refused by the
/// derived `MapAccess` visitor.
///
/// Projection binding: `surql/load_ul_activation_graph.surql` selects exactly
/// `type::string(from) AS from_ref, type::string(to) AS to_ref` for all six
/// relation families, so no record id and no further column reaches this
/// struct. An added, renamed or re-derived projected column must be reviewed
/// here; it is not absorbed as an unknown member.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawActivationRelation {
    pub(super) from_ref: String,
    pub(super) to_ref: String,
}

/// Transport decoder for the whole activation-graph row set: derived struct,
/// no `flatten`, no tag, no `alias`. Unknown completeness/source/lineage
/// members are refused (`deny_unknown_fields`).
///
/// Every family key is REQUIRED and none carries `#[serde(default)]`. The
/// single production projection, `surql/load_ul_activation_graph.surql`, binds
/// each family as `LET $<family> = SELECT … ;` and closes with an object
/// literal listing all seven keys:
///
/// ```text
/// RETURN { co_change: …, card_covers: …, capsule_covers: …,
///           concept_implemented_by: …, concept_depends_on: …,
///           supports: …, verified_by: … };
/// ```
///
/// A `SurrealDB` `SELECT` always yields an array, so a genuinely empty family
/// arrives as `[]` and a family with no rows is not an absent key. The
/// projection has exactly one revision (introduced with the decoder in
/// `8830234a9`, `crates/eliot-store/src/surql/load_ul_activation_graph.surql`)
/// and it already returned all seven keys, so no versioned historical partial
/// shape exists and no compatibility owner is admitted here. An absent family
/// is a partial or foreign transport and is refused as `StoreError::Decode`
/// instead of being read as a known-empty graph, because an omitted family
/// would otherwise silently remove edges from the graph that spreading
/// activation consumes. `has_default`/`deny_unknown_fields` in the shared
/// boundary inventory must follow this shape.
///
/// Sole production decode caller: `CanonicalStore::load_ul_activation_graph`
/// in `crates/eliot-store/src/canonical_store.rs`, which is also the only
/// construction site of `eliot_types::UlActivationGraphRows` in production
/// source. A second decode of this record from another query, or a
/// construction of the public projection that bypasses it, invalidates this
/// repair and must be reviewed at that call site.
///
/// Preceding `Value` normalization boundary: the query result already arrives
/// materialized as `serde_json::Value` from the `SurrealDB` WebSocket RPC ingress
/// `SurrealRpc::request` → `parse_response` (`serde_json::from_str`,
/// `crates/eliot-store/src/surreal_rpc.rs:173`), and is re-materialized by
/// `serde_json::from_value` in `decode_value`
/// (`crates/eliot-store/src/canonical_store.rs:4686`). Lexical duplicate JSON
/// keys are collapsed at that ingress parse, before these attributes run, so
/// this decoder proves refusal of unknown and absent members of the already
/// normalized projection only. Duplicate-sensitive validation of the original
/// response bytes belongs to the transport ingress owner
/// (`crates/eliot-store/src/surreal_rpc.rs:173`); no downstream Serde attribute
/// is claimed to prove those bytes.
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
