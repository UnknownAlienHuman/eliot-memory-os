//! Focused query/DTO parity guard for the observability receipt projections
//! (issue #2990).
//!
//! Surreal's implicit record `id` is not a public control field of
//! `ObservabilityWriteReceipt`. Both receipt-returning contours must therefore
//! project the stored CONTENT keys exactly, and every result branch must carry
//! the same closed field set, so the strict `deny_unknown_fields` decode stays
//! exact on every path instead of only on the branch that happened to omit it.
//!
//! This guard needs no database: it reads the checked-in Surreal templates and
//! the closed DTO. The real-Surreal fresh/replay/conflict/readback execution
//! proofs are not claimed here.

// The helpers below parse fixed literals and inspect a closed DTO. A malformed
// literal must fail as a named test failure, which is the intent here; this is
// the fixture-helper convention already used across these crates.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::str::FromStr;

use eliot_types::{
    ObservabilityKind, ObservabilityWriteReceipt, ObservabilityWriteStatus, ProjectId, TaskId,
    WriteId,
};
use serde_json::{Value, json};

const APPLY_OBSERVABILITY: &str = include_str!("../src/surql/apply_observability.surql");
const RECEIPT_BY_ID: &str = include_str!("../src/surql/observability_receipt_by_id.surql");

/// The exact public receipt field set, in DTO declaration order.
const RECEIPT_FIELDS: [&str; 9] = [
    "write_id",
    "record_id",
    "project_id",
    "task_id",
    "kind",
    "input_hash",
    "status",
    "rejected_reason",
    "created_at",
];

/// One receipt covering every field, used to read the DTO's real key set.
fn receipt() -> ObservabilityWriteReceipt {
    ObservabilityWriteReceipt {
        write_id: WriteId::from_str("00000000-0000-0000-0000-000000000001").unwrap(),
        record_id: "record-2990-1".to_owned(),
        project_id: ProjectId::from_str("00000000-0000-0000-0000-000000000002").unwrap(),
        task_id: Some(TaskId::from_str("00000000-0000-0000-0000-000000000003").unwrap()),
        kind: ObservabilityKind::MemoryInfluenceTrace,
        input_hash: "a".repeat(64),
        status: ObservabilityWriteStatus::Committed,
        rejected_reason: None,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

/// The DTO's serialized key set, read from the type itself.
fn dto_keys() -> Vec<String> {
    let value = serde_json::to_value(receipt()).unwrap();
    let mut keys: Vec<String> = value
        .as_object()
        .expect("a receipt serializes as an object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    keys
}

/// Reads the member names of the result object that contains `sentinel`.
///
/// The templates are hand-written `SurrealQL` formatted one member per line, so
/// the object is read structurally: the nearest opening brace above the
/// sentinel, then the members below it.
fn branch_fields(source: &str, sentinel: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let anchor = lines
        .iter()
        .position(|line| line.contains(sentinel))
        .unwrap_or_else(|| panic!("no result branch names {sentinel}"));
    let open = lines[..anchor]
        .iter()
        .rposition(|line| line.trim() == "{")
        .unwrap_or_else(|| panic!("no result object opens above {sentinel}"));
    lines[open + 1..]
        .iter()
        .take_while(|line| !matches!(line.trim(), "}" | "};"))
        .filter_map(|line| {
            line.trim()
                .trim_end_matches(',')
                .split_once(':')
                .map(|(name, _)| name.to_owned())
        })
        .collect()
}

/// The stored CONTENT member names of the receipt table upsert.
fn stored_receipt_fields() -> Vec<String> {
    let lines: Vec<&str> = APPLY_OBSERVABILITY.lines().collect();
    let anchor = lines
        .iter()
        .position(|line| line.contains("UPSERT type::record('observability_receipt'"))
        .expect("the fresh-commit arm upserts the receipt table");
    lines[anchor + 1..]
        .iter()
        .take_while(|line| !matches!(line.trim(), "}" | "};"))
        .filter_map(|line| {
            line.trim()
                .trim_end_matches(',')
                .split_once(':')
                .map(|(name, _)| name.to_owned())
        })
        .collect()
}

#[test]
fn the_receipt_dto_is_exactly_the_nine_public_members() {
    let expected: Vec<String> = RECEIPT_FIELDS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let mut sorted_expected = expected.clone();
    sorted_expected.sort();
    assert_eq!(dto_keys(), sorted_expected);
    // The closed field set is exactly these nine: a tenth member is refused
    // rather than silently dropped, which is what makes Surreal's record `id`
    // an integrity error instead of a tolerated extra.
    let mut with_id = serde_json::to_value(receipt()).unwrap();
    with_id
        .as_object_mut()
        .expect("a receipt serializes as an object")
        .insert("id".to_owned(), json!("observability_receipt:1"));
    assert!(serde_json::from_value::<ObservabilityWriteReceipt>(with_id).is_err());
}

#[test]
fn optional_receipt_members_keep_their_absence_and_null_shape() {
    let mut absent = serde_json::to_value(receipt()).unwrap();
    let object = absent.as_object_mut().expect("a receipt is an object");
    object.remove("task_id");
    object.remove("rejected_reason");
    assert!(serde_json::from_value::<ObservabilityWriteReceipt>(absent).is_ok());
    let mut nulled = serde_json::to_value(receipt()).unwrap();
    let object = nulled.as_object_mut().expect("a receipt is an object");
    object.insert("task_id".to_owned(), Value::Null);
    object.insert("rejected_reason".to_owned(), Value::Null);
    let decoded: ObservabilityWriteReceipt =
        serde_json::from_value(nulled).expect("NONE decodes as an absent optional");
    assert_eq!(decoded.task_id, None);
    assert_eq!(decoded.rejected_reason, None);
}

#[test]
fn every_observability_result_branch_carries_the_same_nine_members() {
    let expected: Vec<String> = RECEIPT_FIELDS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    // Exact idempotent replay, changed-input conflict and immutable-record
    // conflict each build the public receipt explicitly, and the fresh commit
    // stores the same set. A branch that added, dropped or renamed a member
    // fails here instead of decoding differently from its siblings.
    for sentinel in [
        "'idempotent_replay'",
        "'observability_write_id_conflict'",
        "'immutable_observability_record_conflict'",
    ] {
        assert_eq!(
            branch_fields(APPLY_OBSERVABILITY, sentinel),
            expected,
            "the {sentinel} branch must project exactly the public receipt members"
        );
    }
    assert_eq!(stored_receipt_fields(), expected);
}

#[test]
fn no_returned_observability_receipt_carries_the_surreal_record_id() {
    // The fresh-commit arm returns the stored receipt with the record id
    // omitted, exactly once.
    assert_eq!(
        APPLY_OBSERVABILITY
            .matches("SELECT * OMIT id FROM ONLY type::record('observability_receipt'")
            .count(),
        1
    );
    // The only bare `SELECT *` against the receipt table is the existence read
    // that drives replay/conflict decisions; it never crosses the Rust decode
    // boundary. A second one would be a returned metadata leak.
    assert_eq!(
        APPLY_OBSERVABILITY
            .matches("SELECT * FROM ONLY type::record('observability_receipt'")
            .count(),
        1
    );
    assert!(APPLY_OBSERVABILITY.contains("LET $existing_receipt ="));
    // The readback contour is the same projection over the write identity.
    assert!(
        RECEIPT_BY_ID.contains(
            "SELECT * OMIT id FROM ONLY type::record('observability_receipt', $write_id)"
        )
    );
    assert!(!RECEIPT_BY_ID.contains("SELECT * FROM ONLY"));
}
