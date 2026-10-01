//! Activation-graph derived report/projection data-model cell — decoded graph-row transport only.
//! Architecture A13.2 (Kernel and failure domains): minimal live Kernel preserves canonical history, fencing, health and recovery entrypoint and does not depend on model/Dreamer/graph/provider/UI; this cell owns no canonical state, authority, or write path.
//! Implementation I16.1 (Four surfaces): operational logs, metrics, durable audit, and reports — reports are Human/agent projections generated from canonical state ("prose not truth"); this cell is the I16.1 report/projection truth-boundary handle for UL activation graph rows (`CoChange` plus Card/Capsule/Concept/Support/Verified edges). Reports/projections are not truth/authority; they are derived, rebuildable, and must not confer canonical write authority.
//! Mechanical extraction from `crates/eliot-store/src/canonical_store.rs` — preserves exact behavior, public API, imports, serde shape, and `CanonicalStore` facade. No semantic redesign and no canonical write-authority change. Excludes provider/handshake/migration/atomic-write, capacity/L2/recall, and Dreamer/Luna semantics.
//!
//! Transport decode boundary (#940). These two records are the real decoder on
//! the production activation-graph path:
//!
//! ```text
//! eliot_engine::ul::activation::ActivationEngine::activate
//! → CanonicalStore::load_ul_activation_graph
//! → execute_value(LoadUlActivationGraph)
//! → decode_value::<RawActivationGraphRows>  (serde_json::from_value)
//! → eliot_types::UlActivationGraphRows
//! ```
//!
//! The closed public projection is constructed only after this decode, so it
//! cannot reject anything erased here. A family may therefore never be
//! defaulted to an empty vector, and no member may be discarded silently:
//! absence of evidence is not evidence of an empty graph.

/// Transport decoder: derived struct, no `flatten`, no tag, no `alias`.
/// Unknown member keys are refused (`deny_unknown_fields`); duplicate member
/// keys are already refused by the derived `MapAccess` visitor.
///
/// Bound projection: `surql/load_ul_activation_graph.surql` selects exactly
/// `type::string(from) AS from_ref, type::string(to) AS to_ref` for all six
/// relation families, so no record id or extra column reaches this struct.
/// An added, renamed or re-derived projected column invalidates this decoder
/// and must be reviewed here rather than absorbed.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawActivationRelation {
    pub(super) from_ref: String,
    pub(super) to_ref: String,
}

/// Transport decoder: derived struct, no `flatten`, no tag, no `alias`.
/// Unknown completeness/source/lineage members are refused
/// (`deny_unknown_fields`); duplicate member keys are already refused by the
/// derived `MapAccess` visitor.
///
/// Every family key is REQUIRED, and none carries `#[serde(default)]`.
/// `surql/load_ul_activation_graph.surql` closes with
///
/// ```text
/// RETURN { co_change: …, card_covers: …, capsule_covers: …,
///           concept_implemented_by: …, concept_depends_on: …,
///           supports: …, verified_by: … };
/// ```
///
/// so a genuinely empty family arrives as `[]` and never as an absent key.
/// Absence is a partial or foreign transport shape; it is refused here as
/// `StoreError::Decode` instead of being read as a known-empty graph, because
/// an omitted family would otherwise remove edges from the graph that
/// spreading activation consumes.
///
/// Sole production caller: `CanonicalStore::load_ul_activation_graph` in
/// `crates/eliot-store/src/canonical_store.rs`, the only construction site of
/// `eliot_types::UlActivationGraphRows` in production source. A second decode
/// of this record from any other query, or a construction of the public
/// projection that does not pass through it, invalidates this repair.
///
/// Preceding `Value` normalization boundary: the query result already reaches
/// this decoder materialized as `serde_json::Value`, via
/// `CanonicalStore::execute_value` → `last_query_result` → `decode_value`
/// (`serde_json::from_value`). Lexical duplicate JSON keys are collapsed by
/// that parse before these attributes run. This decoder therefore proves
/// refusal of unknown and absent members of the materialized projection only;
/// duplicate-sensitive validation of the original response bytes belongs to
/// the SurrealDB transport ingress owner (`DbClientSet::execute_named` and
/// `SurrealServerSupervisor`), and no downstream attribute is claimed to
/// prove those bytes.
///
/// Inventory rows closed by this decoder. The #929 integrator records the
/// owner; this file does not edit the shared boundary artifact:
/// `eliot-store:crates/eliot-store/src/canonical_activation_graph_models.rs:derive:RawActivationGraphRows:<root>`
/// and `eliot-store:crates/eliot-store/src/canonical_activation_graph_models.rs:derive:RawActivationRelation:<root>`
/// (both inventoried `owner = UNASSIGNED`, `repair_child = UNASSIGNED`,
/// `repair_readiness = BLOCKED`).
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod activation_graph_transport_tests {
    use super::{RawActivationGraphRows, RawActivationRelation};

    const PROJECT: &str = "0196a1b2-c3d4-7e5f-8000-bbbb00000002";

    /// One projected `co_change` element, assembled by concatenation so no
    /// fixture depends on format-string expansion.
    fn co_change_edge() -> String {
        [
            r#"{"edge_id":"edge-1","project_id":""#,
            PROJECT,
            r#"","path_a":"a.rs","path_b":"b.rs","support":3,"confidence_ab":0.75,"confidence_ba":0.5,"last_cochange_at_unix":1720000000,"static_edge_exists":true,"mining_run_ref":"run-1","cue_bindings":[]}"#,
        ]
        .concat()
    }

    fn seven_key_projection() -> String {
        format!(
            "{{\"co_change\":[{}],\"card_covers\":[{{\"from_ref\":\"card:a\",\"to_ref\":\"card:b\"}}],\"capsule_covers\":[],\"concept_implemented_by\":[],\"concept_depends_on\":[{{\"from_ref\":\"concept:a\",\"to_ref\":\"concept:b\"}}],\"supports\":[],\"verified_by\":[]}}",
            co_change_edge()
        )
    }

    // WORK_UNIT_CASE: 940/1
    #[test]
    fn genuine_projection_with_empty_families_decodes() {
        let raw = seven_key_projection();
        let rows: RawActivationGraphRows =
            serde_json::from_str(&raw).expect("genuine 7-key projection must decode");
        assert_eq!(rows.co_change.len(), 1);
        assert_eq!(rows.co_change[0].edge_id, "edge-1");
        assert_eq!(rows.card_covers.len(), 1);
        assert_eq!(rows.concept_depends_on.len(), 1);
        assert!(rows.capsule_covers.is_empty());
        assert!(rows.concept_implemented_by.is_empty());
        assert!(rows.supports.is_empty());
        assert!(rows.verified_by.is_empty());
        // Same payload through the production `decode_value` boundary
        // (`serde_json::from_value`): required must not mean non-empty required.
        let value: serde_json::Value = serde_json::from_str(&raw).expect("fixture must parse");
        let via_value: RawActivationGraphRows =
            serde_json::from_value(value).expect("production Value boundary must accept");
        assert_eq!(via_value.co_change.len(), 1);
        assert!(via_value.verified_by.is_empty());
    }

    // WORK_UNIT_CASE: 940/2
    #[test]
    fn absent_family_is_refused_not_defaulted() {
        let raw = "{\"co_change\":[],\"card_covers\":[],\"capsule_covers\":[],\"concept_implemented_by\":[],\"concept_depends_on\":[],\"supports\":[]}";
        let err = serde_json::from_str::<RawActivationGraphRows>(raw)
            .expect_err("6-key payload must be refused");
        let message = err.to_string();
        assert!(
            message.contains("verified_by"),
            "refusal must name the absent family, got: {message}"
        );
        let value: serde_json::Value = serde_json::from_str(raw).expect("fixture must parse");
        let value_err = serde_json::from_value::<RawActivationGraphRows>(value)
            .expect_err("production Value boundary must also refuse");
        assert!(
            value_err.to_string().contains("verified_by"),
            "Value-boundary refusal must name the absent family"
        );
    }

    // WORK_UNIT_CASE: 940/3
    #[test]
    fn unknown_transport_member_is_refused() {
        let mut value: serde_json::Value =
            serde_json::from_str(&seven_key_projection()).expect("fixture must parse");
        value
            .as_object_mut()
            .expect("projection must be an object")
            .insert(
                "lineage".to_owned(),
                serde_json::Value::String("newer-schema".to_owned()),
            );
        let raw = serde_json::to_string(&value).expect("fixture must serialize");
        let err = serde_json::from_str::<RawActivationGraphRows>(&raw)
            .expect_err("8-key payload must be refused");
        let message = err.to_string();
        assert!(
            message.contains("lineage"),
            "refusal must name the unknown member, got: {message}"
        );
        let nested = "{\"from_ref\":\"card:a\",\"to_ref\":\"card:b\",\"source\":\"newer-schema\"}";
        let nested_err = serde_json::from_str::<RawActivationRelation>(nested)
            .expect_err("unknown relation member must be refused");
        assert!(nested_err.to_string().contains("source"));
    }

    // WORK_UNIT_CASE: 940/4
    #[test]
    fn null_family_fails_closed() {
        let raw = "{\"co_change\":[],\"card_covers\":[],\"capsule_covers\":[],\"concept_implemented_by\":[],\"concept_depends_on\":[],\"supports\":null,\"verified_by\":[]}";
        let err = serde_json::from_str::<RawActivationGraphRows>(raw)
            .expect_err("null family must fail closed, never decode as empty");
        assert!(!err.to_string().is_empty());
    }
}
