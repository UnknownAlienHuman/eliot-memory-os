//! Post-retirement legacy boundary regression (issue #835).
//!
//! After removing the transitional `CueKind` alias, the historical V1
//! vocabulary must keep verifying byte-for-byte: closed variants, exact wire
//! spellings, valid roundtrips, unknown rejection, schema title, descriptor
//! pins, and deterministic page/hash identity. This suite proves preservation;
//! absence of the alias itself is proved by the updated boundary oracle
//! (cases 706/11-14, 706/29) and the 835 retirement coordinator.

use eliot_types::ul::cue::LegacyCueKindV1MigrationDescriptor;
use eliot_types::{
    BlobRef, CueBinding, CueBindingPage, CueMatchMode, CueStrength, LegacyCueKindV1, ProjectId,
    cue_binding_page_id, cue_binding_page_set_hash, cue_row_id, normalize_binding,
};
use serde_json::Value;

fn all_variants() -> [(LegacyCueKindV1, &'static str); 10] {
    [
        (LegacyCueKindV1::FilePath, "file_path"),
        (LegacyCueKindV1::DirPath, "dir_path"),
        (LegacyCueKindV1::Symbol, "symbol"),
        (LegacyCueKindV1::ErrorSignature, "error_signature"),
        (LegacyCueKindV1::CommandPattern, "command_pattern"),
        (LegacyCueKindV1::Dependency, "dependency"),
        (LegacyCueKindV1::ApiSurface, "api_surface"),
        (LegacyCueKindV1::TaskClass, "task_class"),
        (LegacyCueKindV1::Subsystem, "subsystem"),
        (LegacyCueKindV1::Concept, "concept"),
    ]
}

#[test]
fn retired_v1_variants_and_wire_spellings_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(LegacyCueKindV1MigrationDescriptor::VARIANT_COUNT, 10);
    assert_eq!(
        LegacyCueKindV1MigrationDescriptor::WIRE_SPELLINGS,
        all_variants().map(|(_, spelling)| spelling)
    );
    for (variant, spelling) in all_variants() {
        assert_eq!(variant.as_str(), spelling);
        let encoded = serde_json::to_value(variant)?;
        assert_eq!(encoded, Value::String(spelling.to_owned()));
        let decoded: LegacyCueKindV1 = serde_json::from_value(encoded)?;
        assert_eq!(decoded, variant);
    }
    Ok(())
}

#[test]
fn retired_v1_rejects_unknown_missing_and_empty() {
    for spelling in [
        "unknown",
        "missing",
        "",
        "Path",
        "FILE_PATH",
        "file-path",
        "cue",
        "null",
        "relation_edge",
        "none",
    ] {
        let raw = format!("\"{spelling}\"");
        assert!(
            serde_json::from_str::<LegacyCueKindV1>(&raw).is_err(),
            "V1 must reject spelling: {spelling:?}"
        );
    }
    assert!(serde_json::from_str::<LegacyCueKindV1>("null").is_err());
    let empty_object = "{}";
    assert!(serde_json::from_str::<LegacyCueKindV1>(empty_object).is_err());
}

#[test]
fn retired_v1_schema_title_and_descriptor_pins_unchanged() -> Result<(), Box<dyn std::error::Error>>
{
    let schema = schemars::schema_for!(LegacyCueKindV1);
    let value = serde_json::to_value(&schema)?;
    assert_eq!(
        value.get("title").and_then(Value::as_str),
        Some("LegacyCueKindV1")
    );
    assert_eq!(
        LegacyCueKindV1MigrationDescriptor::SOURCE_SCHEMA,
        "eliot-types.ul.cue.LegacyCueKindV1"
    );
    assert_eq!(LegacyCueKindV1MigrationDescriptor::SOURCE_GENERATION, "v1");
    assert_eq!(
        LegacyCueKindV1MigrationDescriptor::TARGET_MODULE,
        "smart.cue.contracts"
    );
    assert_eq!(
        LegacyCueKindV1MigrationDescriptor::TARGET_CRATE,
        "eliot-cue-contracts"
    );
    assert_eq!(LegacyCueKindV1MigrationDescriptor::TARGET_REVISION, "2.0.0");
    assert_eq!(
        LegacyCueKindV1MigrationDescriptor::TARGET_DIGEST,
        "a5412833fde7b3cb1e214774061d04e21ab6773870180ffeff5959a8242ff850"
    );
    assert_eq!(
        LegacyCueKindV1MigrationDescriptor::MANIFEST,
        "crates/eliot-types/tests/data/cue_kind_migration.toml"
    );
    Ok(())
}

fn concept_binding(value: &str) -> CueBinding {
    CueBinding {
        cue_kind: LegacyCueKindV1::Concept,
        cue_value: value.to_owned(),
        match_mode: CueMatchMode::Exact,
        strength: CueStrength::Primary,
        expected_reuse_note: Some("retirement regression".to_owned()),
    }
}

#[test]
fn retired_v1_normalization_and_bytes_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let normalized = normalize_binding(concept_binding("  Spaced   Value "), None)?;
    assert_eq!(normalized.cue_value, "spaced   value");
    let encoded = serde_json::to_vec(&normalized)?;
    let decoded: CueBinding = serde_json::from_slice(&encoded)?;
    assert_eq!(decoded.cue_kind, LegacyCueKindV1::Concept);
    assert_eq!(decoded.cue_value, "spaced   value");
    Ok(())
}

#[test]
fn retired_v1_page_and_hash_identity_deterministic() {
    let project = ProjectId::new_v7();
    let first = cue_row_id(
        project,
        LegacyCueKindV1::Concept,
        CueMatchMode::Exact,
        "capacity",
        "memory:one",
    );
    let second = cue_row_id(
        project,
        LegacyCueKindV1::Concept,
        CueMatchMode::Exact,
        "capacity",
        "memory:one",
    );
    assert_eq!(first, second);
    assert!(first.starts_with("cue:"));
    let other = cue_row_id(
        project,
        LegacyCueKindV1::Symbol,
        CueMatchMode::Exact,
        "capacity",
        "memory:one",
    );
    assert_ne!(first, other);
    let blob = BlobRef {
        algorithm: "blake3".to_owned(),
        digest_hex: "c".repeat(64),
        size_bytes: 1,
        relative_path: "cc/c.blob".to_owned(),
    };
    let page_id = cue_binding_page_id("memory:retire", &blob, 0, &[concept_binding("idea")]);
    assert!(page_id.starts_with("cue-page:"));
    let empty: Vec<CueBindingPage> = Vec::new();
    assert_eq!(
        cue_binding_page_set_hash(&empty),
        cue_binding_page_set_hash(&empty)
    );
}
