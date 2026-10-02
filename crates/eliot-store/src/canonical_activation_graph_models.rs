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

#[cfg(test)]
mod tests {
    use eliot_types::{StrictJsonErrorKind, strict_json_has_no_duplicate_members};
    use serde_json::Value;

    use super::{RawActivationGraphRows, RawActivationRelation};

    /// The family keys the single production projection binds, in the order its
    /// closing object literal lists them.
    ///
    /// A rename, removal, addition or reordering of a projected family is a
    /// transport-shape change, and `projected_families_are_exactly_the_admitted_families`
    /// is what makes such a change fail here rather than silently become an
    /// unknown member or a defaulted-empty family.
    const PROJECTED_FAMILIES: [&str; 7] = [
        "co_change",
        "card_covers",
        "capsule_covers",
        "concept_implemented_by",
        "concept_depends_on",
        "supports",
        "verified_by",
    ];

    /// Bytes as `NamedSurqlOp::LoadUlActivationGraph` answers them: every family
    /// key present, one co-change edge and one card-cover relation.
    ///
    /// `static_edge_exists` is written as an explicit `null` because
    /// `eliot_types::CoChangeEdge` declares it as `Option<bool>` with no serde
    /// default: absent, explicit-null and present are three different facts, and
    /// only the explicit null is what the stored `receipt_body` of a
    /// `co_change_edge` canonical record can carry for an edge with no static
    /// counterpart. `serde_json` reports that null through `visit_none`, so this
    /// is the shape a closure must keep admitting.
    const PROJECTED_ROWS: &[u8] = br#"{
      "co_change": [
        {
          "edge_id": "edge-1",
          "project_id": "01920000-0000-7000-8000-000000000001",
          "path_a": "src/a.rs",
          "path_b": "src/b.rs",
          "support": 2,
          "confidence_ab": 0.5,
          "confidence_ba": 0.25,
          "last_cochange_at_unix": 1750000000,
          "static_edge_exists": null,
          "mining_run_ref": "mining-run-1",
          "cue_bindings": []
        }
      ],
      "card_covers": [{"from_ref": "card:a", "to_ref": "concept:a"}],
      "capsule_covers": [],
      "concept_implemented_by": [],
      "concept_depends_on": [],
      "supports": [],
      "verified_by": []
    }"#;

    /// Decodes one transport document from the bytes the projection produced.
    ///
    /// Every fixture below is a byte literal. A `serde_json::Value` fixture is
    /// already the collapsed projection of those bytes, so it cannot observe the
    /// lexical facts the duplicate-member test exists to pin.
    fn rows_from_wire(bytes: &[u8]) -> Result<RawActivationGraphRows, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Decodes one transport document the way the production caller does: the
    /// already-normalized query result re-materialized by `decode_value`'s
    /// `serde_json::from_value` (`crates/eliot-store/src/canonical_store.rs`).
    ///
    /// `decode_value` is private to `canonical_store`, so this mirrors its single
    /// call rather than reaching across the module boundary. The differences the
    /// raw-byte helper can still see are named at their own call site, not here.
    fn rows_from_projected_value(
        bytes: &[u8],
    ) -> Result<RawActivationGraphRows, serde_json::Error> {
        serde_json::from_value(serde_json::from_slice::<Value>(bytes)?)
    }

    /// The family keys the production projection's closing object literal lists.
    fn projected_family_keys() -> Result<Vec<String>, String> {
        let query = include_str!("surql/load_ul_activation_graph.surql");
        let (_, returned) = query.rsplit_once("RETURN {").ok_or_else(|| {
            "activation-graph projection no longer closes with a RETURN object literal".to_owned()
        })?;
        let literal = returned
            .split_once('}')
            .map(|(literal, _)| literal)
            .ok_or_else(|| "projection RETURN object literal is unterminated".to_owned())?;
        Ok(literal
            .split(',')
            .filter_map(|entry| entry.split_once(':'))
            .map(|(key, _)| key.trim().to_owned())
            .collect())
    }

    #[test]
    fn projected_row_bytes_decode_into_both_transport_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rows = rows_from_wire(PROJECTED_ROWS)?;

        assert_eq!(rows.co_change.len(), 1);
        assert_eq!(rows.co_change[0].edge_id, "edge-1");
        assert_eq!(rows.co_change[0].support, 2);
        // The explicit null is admitted, so a co-change edge without a static
        // counterpart is not confused with an edge that lost the member.
        assert_eq!(rows.co_change[0].static_edge_exists, None);
        assert!(rows.co_change[0].cue_bindings.is_empty());

        assert_eq!(rows.card_covers.len(), 1);
        assert_eq!(rows.card_covers[0].from_ref, "card:a");
        assert_eq!(rows.card_covers[0].to_ref, "concept:a");
        assert!(rows.capsule_covers.is_empty());
        assert!(rows.concept_implemented_by.is_empty());
        assert!(rows.concept_depends_on.is_empty());
        assert!(rows.supports.is_empty());
        assert!(rows.verified_by.is_empty());

        // The same bytes through the production `from_value` normalization: a
        // valid projection is not refused on either entry.
        let normalized = rows_from_projected_value(PROJECTED_ROWS)?;
        assert_eq!(normalized.co_change.len(), 1);
        assert_eq!(normalized.card_covers.len(), 1);
        Ok(())
    }

    #[test]
    fn an_unknown_completeness_member_is_refused_on_the_row_set() {
        // `total_ul_edges` is a real member of `eliot_types::UlGraphInventory`,
        // recomputed by the Store owner after the readiness decode
        // (`canonical_store.rs`), and it is not projected here. Carrying it on
        // the activation-graph transport would be an unsupported completeness
        // claim, and admitting it silently is the defect this closure removes.
        let with_total = br#"{
          "co_change": [],
          "card_covers": [],
          "capsule_covers": [],
          "concept_implemented_by": [],
          "concept_depends_on": [],
          "supports": [],
          "verified_by": [],
          "total_ul_edges": 0
        }"#;
        assert!(rows_from_wire(with_total).is_err());
        assert!(rows_from_projected_value(with_total).is_err());

        // The same document without the member is admitted, so the unknown
        // member is attributable as the whole cause rather than one refusal
        // among several.
        assert!(rows_from_wire(PROJECTED_ROWS).is_ok());
    }

    #[test]
    fn an_absent_relation_family_is_refused_instead_of_reading_as_an_empty_graph() {
        // A `SurrealDB` `SELECT` always yields an array, so a family with no rows
        // arrives as `[]` and a family with no rows is not an absent key. An
        // absent key is a partial or foreign transport: reading it as an empty
        // family would remove that family's edges from the graph that spreading
        // activation consumes.
        let without_verified_by = br#"{
          "co_change": [],
          "card_covers": [],
          "capsule_covers": [],
          "concept_implemented_by": [],
          "concept_depends_on": [],
          "supports": []
        }"#;
        assert!(rows_from_wire(without_verified_by).is_err());
        assert!(rows_from_projected_value(without_verified_by).is_err());

        // Every family present and empty is the legitimate known-empty graph,
        // and it is admitted on both entries.
        let all_families_empty = br#"{
          "co_change": [],
          "card_covers": [],
          "capsule_covers": [],
          "concept_implemented_by": [],
          "concept_depends_on": [],
          "supports": [],
          "verified_by": []
        }"#;
        assert!(rows_from_wire(all_families_empty).is_ok());
        assert!(rows_from_projected_value(all_families_empty).is_ok());
    }

    #[test]
    fn an_unknown_or_missing_member_is_refused_on_a_projected_relation_row(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The relation families are projected as exactly two aliased columns, so
        // a carried record id, weight or lineage member is an added projected
        // column that must be reviewed rather than absorbed.
        let with_extra_column = br#"{"from_ref": "card:a", "to_ref": "concept:a", "id": "r-1"}"#;
        assert!(serde_json::from_slice::<RawActivationRelation>(with_extra_column).is_err());

        let without_to_ref = br#"{"from_ref": "card:a"}"#;
        assert!(serde_json::from_slice::<RawActivationRelation>(without_to_ref).is_err());

        // Both refusals belong to the relation record itself: the same two
        // columns alone are admitted.
        let exact: RawActivationRelation =
            serde_json::from_slice(br#"{"from_ref": "card:a", "to_ref": "concept:a"}"#)?;
        assert_eq!(exact.from_ref, "card:a");
        assert_eq!(exact.to_ref, "concept:a");

        // The same unknown member nested inside the row set is refused there too,
        // so an added projected column cannot reach the public projection by
        // hiding in a family array.
        let nested_extra = br#"{
          "co_change": [],
          "card_covers": [{"from_ref": "card:a", "to_ref": "concept:a", "id": "r-1"}],
          "capsule_covers": [],
          "concept_implemented_by": [],
          "concept_depends_on": [],
          "supports": [],
          "verified_by": []
        }"#;
        assert!(rows_from_wire(nested_extra).is_err());
        assert!(rows_from_projected_value(nested_extra).is_err());
        Ok(())
    }

    #[test]
    fn a_repeated_member_is_refused_by_the_derive_and_by_the_raw_ingress_owner() {
        let repeated_family = br#"{
          "co_change": [],
          "co_change": [],
          "card_covers": [],
          "capsule_covers": [],
          "concept_implemented_by": [],
          "concept_depends_on": [],
          "supports": [],
          "verified_by": []
        }"#;
        let repeated_member = br#"{
          "co_change": [],
          "card_covers": [{"from_ref": "card:a", "from_ref": "card:b", "to_ref": "concept:a"}],
          "capsule_covers": [],
          "concept_implemented_by": [],
          "concept_depends_on": [],
          "supports": [],
          "verified_by": []
        }"#;

        // On raw bytes the derived `MapAccess` visitor refuses the repeated
        // member itself, at the object that carries it.
        assert!(rows_from_wire(repeated_family).is_err());
        assert!(rows_from_wire(repeated_member).is_err());

        // The production caller does not reach that refusal, and this is not a
        // defect of these derives: `parse_response`
        // (`crates/eliot-store/src/surreal_rpc.rs`) already refuses the lexical
        // duplicate on the raw response frame, before the query result becomes
        // the `Value` that `decode_value` re-materializes. That single shared
        // raw-ingress gate is reused here as evidence, not reimplemented: the
        // same `eliot_types::strict_json` entry point
        // `canonical_record.rs` consumes.
        assert!(matches!(
            strict_json_has_no_duplicate_members(repeated_family),
            Err(error) if error.kind == StrictJsonErrorKind::DuplicateKey
        ));
        assert!(matches!(
            strict_json_has_no_duplicate_members(repeated_member),
            Err(error) if error.kind == StrictJsonErrorKind::DuplicateKey
        ));
        assert!(strict_json_has_no_duplicate_members(PROJECTED_ROWS).is_ok());

        // Past that gate the bytes are duplicate-free, so the last-wins
        // projection `decode_value` actually receives decodes normally. These
        // derives therefore make no claim about the original response bytes.
        assert!(rows_from_projected_value(repeated_family).is_ok());
        assert!(rows_from_projected_value(repeated_member).is_ok());
    }

    #[test]
    fn projected_families_are_exactly_the_admitted_families(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let query = include_str!("surql/load_ul_activation_graph.surql");
        assert_eq!(projected_family_keys()?, PROJECTED_FAMILIES.to_vec());

        // Each of the six relation families projects exactly the two aliased
        // columns the relation record admits, so no record id and no further
        // column can reach it unnoticed.
        assert_eq!(
            query.matches("type::string(from) AS from_ref").count(),
            6_usize
        );
        assert_eq!(query.matches("type::string(to) AS to_ref").count(), 6_usize);
        assert!(!query.contains("SELECT *"));

        // The co-change family is `SELECT VALUE receipt_body`, so its members
        // are closed by the `eliot_types::CoChangeEdge` owner, not by this file.
        assert_eq!(query.matches("SELECT VALUE receipt_body").count(), 1_usize);
        Ok(())
    }
}
