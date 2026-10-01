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

/// Decoder: derived struct, no `flatten`. Unknown member keys are refused;
/// duplicate member keys are already refused by the derived `MapAccess`.
/// Every family key is required: the `LoadUlActivationGraph` projection
/// always emits all seven keys (an empty family arrives as `[]`), so an
/// absent family is a partial transport and must be refused rather than
/// read as a known-empty graph.
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
mod activation_graph_transport_tests {
    use super::{RawActivationGraphRows, RawActivationRelation};

    const PROJECT: &str = "0196a1b2-c3d4-7e5f-8000-bbbb00000002";

    fn co_change_edge() -> String {
        format!(
            "{{\"edge_id\":\"edge-1\",\"project_id\":\"{PROJECT}\",\"path_a\":\"a.rs\",\"path_b\":\"b.rs\",\"support\":3,\"confidence_ab\":0.75,\"confidence_ba\":0.5,\"last_cochange_at_unix\":1720000000,\"static_edge_exists\":true,\"mining_run_ref\":\"run-1\",\"cue_bindings\":[]}}"
        )
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
        let value: serde_json::Value =
            serde_json::from_str(&raw).expect("fixture must parse");
        let via_value: RawActivationGraphRows =
            serde_json::from_value(value).expect("production Value boundary must accept");
        assert_eq!(via_value.co_change.len(), 1);
        assert!(via_value.verified_by.is_empty());
    }

    // WORK_UNIT_CASE: 940/2
    #[test]
    fn absent_family_is_refused_not_defaulted() {
        let raw = format!(
            "{{\"co_change\":[],\"card_covers\":[],\"capsule_covers\":[],\"concept_implemented_by\":[],\"concept_depends_on\":[],\"supports\":[]}}"
        );
        let err = serde_json::from_str::<RawActivationGraphRows>(&raw)
            .expect_err("6-key payload must be refused");
        let message = err.to_string();
        assert!(
            message.contains("verified_by"),
            "refusal must name the absent family, got: {message}"
        );
        let value: serde_json::Value =
            serde_json::from_str(&raw).expect("fixture must parse");
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
        let raw = format!(
            "{{\"co_change\":[],\"card_covers\":[],\"capsule_covers\":[],\"concept_implemented_by\":[],\"concept_depends_on\":[],\"supports\":null,\"verified_by\":[]}}"
        );
        let err = serde_json::from_str::<RawActivationGraphRows>(&raw)
            .expect_err("null family must fail closed, never decode as empty");
        assert!(!err.to_string().is_empty());
    }
}
