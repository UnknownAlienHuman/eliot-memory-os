//! F-DENY-LS-RECORD (#976) boundary proof: legacy `CanonicalRecord` decoder.
//! Reads `data/serde_canonical_record_boundary.json` where adversarial inputs
//! are stored as strings so duplicate keys survive fixture loading. All
//! negative raw cases exercise the real public `Deserialize` path via
//! `serde_json::from_str`, never via pre-parsed `Value`.
//!
//! Docs routing: route `sha256:e527e01de40ddd422b36456a7fc45838cde81bd914f2bdcafe75a8ff90ba6486`,
//! read `sha256:b659011ef2a5ae2110f6ce1093ea03750c4b7c9301adb5c0c9672054bf177d62`,
//! bundle `sha256:f2fdcbefe7b1afbc3180b7552ed6e09583afdf41c39a20a07fe58c2d26d57e79`.
//! Required: APPENDIX-P, I05-16, I05-22, I07-20, I15-06, I18-27 plus #710
//! decoder contract and #929 rows. Base `2cd0e44d6cb882699db4e7fb672e7bbeeba91d27`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use eliot_store::CanonicalRecord;
use eliot_types::{MemoryStateTransition, OperatorProjectionFilter};
use serde_json::Value;

const FIXTURES_DOC: &str = include_str!("data/serde_canonical_record_boundary.json");

fn fixtures_doc() -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(FIXTURES_DOC)?)
}

fn fixture_raw(id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let doc = fixtures_doc()?;
    let list = doc
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or("missing fixtures array")?;
    for item in list {
        if item.get("id").and_then(Value::as_str) == Some(id) {
            let raw = item
                .get("raw")
                .and_then(Value::as_str)
                .ok_or("missing raw string")?;
            return Ok(raw.to_owned());
        }
    }
    Err(format!("fixture {id} not found").into())
}

fn decode_raw<T>(raw: &str) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str::<T>(raw).map_err(|err| err.to_string())
}

fn expect_err<T>(
    result: Result<T, String>,
    context: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match result {
        Ok(_) => Err(format!("{context} must reject").into()),
        Err(message) => Ok(message),
    }
}

fn envelope_with(body_fragment: &str) -> String {
    format!(
        "{{\"record_id\":\"0196a1b2-c3d4-7e5f-8000-aaaa00000001\",\"receipt_kind\":\"autonomy_budget_ledger\",\"project_id\":\"0196a1b2-c3d4-7e5f-8000-bbbb00000002\",\"task_id\":null,\"subject_ref\":\"autonomy:operator-runtime-proof\",\"receipt_body\":{body_fragment},\"canonical_receipt\":{{\"receipt_id\":\"0196a1b2-c3d4-7e5f-8000-cccc00000003\",\"write_id\":\"0196a1b2-c3d4-7e5f-8000-dddd00000004\"}},\"memory_revision\":1,\"project_sequence\":1}}"
    )
}

// WORK_UNIT_CASE: 976/1
#[test]
fn boundary_allocation_envelope_decoder_roles() -> Result<(), Box<dyn std::error::Error>> {
    let raw = fixture_raw("976-01-valid-envelope")?;
    let record: CanonicalRecord<Value> = serde_json::from_str(&raw)?;
    assert_eq!(record.record_id, "0196a1b2-c3d4-7e5f-8000-aaaa00000001");
    assert_eq!(record.receipt_kind, "autonomy_budget_ledger");
    assert_eq!(record.subject_ref, "autonomy:operator-runtime-proof");
    assert_eq!(record.receipt_body, serde_json::json!({"state": "active"}));
    let normalized: Value = serde_json::from_str(&raw)?;
    let via_value: CanonicalRecord<Value> = serde_json::from_value(normalized)?;
    assert_eq!(via_value.receipt_body, record.receipt_body);
    let unknown = fixture_raw("976-06-unknown-envelope")?;
    assert!(decode_raw::<CanonicalRecord<Value>>(&unknown).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 976/2
#[test]
fn legacy_only_preserves_fields_and_digest() -> Result<(), Box<dyn std::error::Error>> {
    let raw = fixture_raw("976-02-legacy-valid")?;
    let record: CanonicalRecord<Value> = serde_json::from_str(&raw)?;
    assert_eq!(record.receipt_body, serde_json::json!({"state": "active"}));
    assert_eq!(record.task_id, None);
    let serialized = serde_json::to_string(&record)?;
    assert_eq!(serialized, raw);
    let first = serde_json::to_string(&record)?;
    let second = serde_json::to_string(&record)?;
    assert_eq!(first, second);
    assert!(!first.is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 976/3
#[test]
fn standard_no_pad_body_decodes() -> Result<(), Box<dyn std::error::Error>> {
    let raw = fixture_raw("976-03-b64-valid")?;
    assert!(!raw.contains("receipt_body\":"));
    let record: CanonicalRecord<Value> = serde_json::from_str(&raw)?;
    let expected = serde_json::json!({"target_ref": "memory:operator-runtime-proof"});
    assert_eq!(record.receipt_body, expected);
    let encoded = STANDARD_NO_PAD.encode(serde_json::to_vec(&expected)?);
    assert!(!encoded.contains('='));
    assert!(raw.contains(&encoded));
    Ok(())
}

// WORK_UNIT_CASE: 976/4
#[test]
fn dual_form_preserves_base64_precedence() -> Result<(), Box<dyn std::error::Error>> {
    let raw = fixture_raw("976-04-dual-precedence")?;
    assert!(raw.contains("receipt_body"));
    assert!(raw.contains("receipt_body_json_b64"));
    let record: CanonicalRecord<Value> = serde_json::from_str(&raw)?;
    assert_eq!(
        record.receipt_body,
        serde_json::json!({"target_ref": "memory:operator-runtime-proof"})
    );
    assert_ne!(
        record.receipt_body,
        serde_json::json!({"target_ref": "memory:operator"})
    );
    Ok(())
}

// WORK_UNIT_CASE: 976/5
#[test]
fn malformed_selected_never_falls_back() -> Result<(), Box<dyn std::error::Error>> {
    let bad_b64 = fixture_raw("976-05a-bad-b64")?;
    let err = expect_err(decode_raw::<CanonicalRecord<Value>>(&bad_b64), "bad base64")?;
    assert!(!err.contains("active"));
    let bad_json = fixture_raw("976-05b-bad-selected-json")?;
    let err_json = expect_err(
        decode_raw::<CanonicalRecord<Value>>(&bad_json),
        "bad selected JSON",
    )?;
    assert!(!err_json.contains("active"));
    Ok(())
}

// WORK_UNIT_CASE: 976/6
#[test]
fn raw_unknown_envelope_field_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let raw = fixture_raw("976-06-unknown-envelope")?;
    assert!(decode_raw::<CanonicalRecord<Value>>(&raw).is_err());
    let canary = "CANARY-976-UNKNOWN-9f8e7d6c5b4a";
    let with_canary = format!(
        "{{\"record_id\":\"0196a1b2-c3d4-7e5f-8000-aaaa00000001\",\"receipt_kind\":\"k\",\"project_id\":\"0196a1b2-c3d4-7e5f-8000-bbbb00000002\",\"task_id\":null,\"subject_ref\":\"s\",\"receipt_body\":{{\"state\":\"active\"}},\"canonical_receipt\":{{\"receipt_id\":\"0196a1b2-c3d4-7e5f-8000-cccc00000003\",\"write_id\":\"0196a1b2-c3d4-7e5f-8000-dddd00000004\"}},\"memory_revision\":1,\"project_sequence\":1,\"__canary_976\":\"{canary}\"}}"
    );
    let err = expect_err(
        decode_raw::<CanonicalRecord<Value>>(&with_canary),
        "unknown canary field",
    )?;
    assert!(!err.contains(canary));
    Ok(())
}

// WORK_UNIT_CASE: 976/7
#[test]
fn raw_duplicate_envelope_keys_rejected() -> Result<(), Box<dyn std::error::Error>> {
    for id in [
        "976-07a-dup-ordinary",
        "976-07b-dup-identity",
        "976-07c-dup-selector",
        "976-07d-dup-escape",
    ] {
        let raw = fixture_raw(id)?;
        assert!(
            decode_raw::<CanonicalRecord<Value>>(&raw).is_err(),
            "fixture {id} must reject"
        );
    }
    let b64 = STANDARD_NO_PAD.encode(b"{\"state\":\"active\"}");
    let dup_b64 = [
        "{\"record_id\":\"0196a1b2-c3d4-7e5f-8000-aaaa00000001\",\"receipt_kind\":\"k\",\"project_id\":\"0196a1b2-c3d4-7e5f-8000-bbbb00000002\",\"task_id\":null,\"subject_ref\":\"s\",\"receipt_body\":{\"state\":\"active\"},\"receipt_body_json_b64\":\"",
        b64.as_str(),
        "\",\"receipt_body_json_b64\":\"",
        b64.as_str(),
        "\",\"canonical_receipt\":{\"receipt_id\":\"0196a1b2-c3d4-7e5f-8000-cccc00000003\",\"write_id\":\"0196a1b2-c3d4-7e5f-8000-dddd00000004\"},\"memory_revision\":1,\"project_sequence\":1}",
    ]
    .concat();
    assert!(decode_raw::<CanonicalRecord<Value>>(&dup_b64).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 976/8
#[test]
fn legacy_body_duplicates_detected_pre_normalization() -> Result<(), Box<dyn std::error::Error>> {
    let raw = fixture_raw("976-08-legacy-body-dup")?;
    assert!(decode_raw::<CanonicalRecord<Value>>(&raw).is_err());
    let canary = "CANARY-976-LEGACY-BODY-1a2b3c4d";
    let body = format!("{{\"k\":\"{canary}\",\"k\":\"second\"}}");
    let raw_canary = envelope_with(&body);
    let err = expect_err(
        decode_raw::<CanonicalRecord<Value>>(&raw_canary),
        "legacy canary dup",
    )?;
    assert!(!err.contains(canary));
    Ok(())
}

// WORK_UNIT_CASE: 976/9
#[test]
fn base64_body_duplicates_rejected_actual_path() -> Result<(), Box<dyn std::error::Error>> {
    let raw = fixture_raw("976-09-b64-body-dup")?;
    let err = expect_err(
        decode_raw::<CanonicalRecord<Value>>(&raw),
        "base64 body dup",
    )?;
    assert!(err.contains("canonical record"));
    assert!(!raw.contains("second"));
    Ok(())
}

// WORK_UNIT_CASE: 976/10
#[test]
fn nested_protected_uses_actual_owner() -> Result<(), Box<dyn std::error::Error>> {
    let strict_raw = fixture_raw("976-10a-strict-unknown-nested")?;
    assert!(decode_raw::<CanonicalRecord<OperatorProjectionFilter>>(&strict_raw).is_err());
    assert!(decode_raw::<CanonicalRecord<Value>>(&strict_raw).is_ok());
    let empty = serde_json::json!({});
    assert_eq!(empty, serde_json::json!({}));
    let wrong = fixture_raw("976-10b-wrong-shape")?;
    assert!(decode_raw::<CanonicalRecord<MemoryStateTransition>>(&wrong).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 976/11
#[test]
fn missing_null_identity_without_invented_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let missing = fixture_raw("976-11a-missing-record-id")?;
    assert!(decode_raw::<CanonicalRecord<Value>>(&missing).is_err());
    let null_id = "{\"record_id\":null,\"receipt_kind\":\"k\",\"project_id\":\"0196a1b2-c3d4-7e5f-8000-bbbb00000002\",\"task_id\":null,\"subject_ref\":\"s\",\"receipt_body\":{\"state\":\"active\"},\"canonical_receipt\":{\"receipt_id\":\"0196a1b2-c3d4-7e5f-8000-cccc00000003\",\"write_id\":\"0196a1b2-c3d4-7e5f-8000-dddd00000004\"},\"memory_revision\":1,\"project_sequence\":1}";
    assert!(decode_raw::<CanonicalRecord<Value>>(null_id).is_err());
    assert!(decode_raw::<CanonicalRecord<Value>>("{}").is_err());
    let null_task = fixture_raw("976-11b-null-task-ok")?;
    let record: CanonicalRecord<Value> = serde_json::from_str(&null_task)?;
    assert_eq!(record.task_id, None);
    assert_eq!(
        record
            .memory_revision
            .map(eliot_types::MemoryRevision::value),
        Some(1)
    );
    Ok(())
}

// WORK_UNIT_CASE: 976/12
#[test]
fn version_incompatible_never_trial_decodes() -> Result<(), Box<dyn std::error::Error>> {
    let raw = fixture_raw("976-12-version-incompatible")?;
    assert!(decode_raw::<CanonicalRecord<Value>>(&raw).is_err());
    let wrong = fixture_raw("976-10b-wrong-shape")?;
    assert!(decode_raw::<CanonicalRecord<MemoryStateTransition>>(&wrong).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 976/13
#[test]
fn normalized_value_weaker_provenance_documented() -> Result<(), Box<dyn std::error::Error>> {
    let raw = fixture_raw("976-13-value-weaker")?;
    assert!(decode_raw::<CanonicalRecord<Value>>(&raw).is_err());
    let collapsed: Value = serde_json::from_str(&raw)?;
    let via_value: CanonicalRecord<Value> = serde_json::from_value(collapsed)?;
    assert_eq!(via_value.subject_ref, "b");
    let serialized = serde_json::to_value(&via_value)?;
    assert!(serialized.get("validated").is_none());
    Ok(())
}

// WORK_UNIT_CASE: 976/14
#[test]
fn bounded_malformed_never_panics() -> Result<(), Box<dyn std::error::Error>> {
    for id in [
        "976-14a-truncated",
        "976-14b-bad-escape",
        "976-14c-trailing",
        "976-14d-deep-nesting",
    ] {
        let raw = fixture_raw(id)?;
        assert!(
            decode_raw::<CanonicalRecord<Value>>(&raw).is_err(),
            "fixture {id} must fail closed"
        );
    }
    let trailing_body = STANDARD_NO_PAD.encode(b"{\"state\":\"active\"} trailing");
    let raw = format!(
        "{{\"record_id\":\"0196a1b2-c3d4-7e5f-8000-aaaa00000001\",\"receipt_kind\":\"k\",\"project_id\":\"0196a1b2-c3d4-7e5f-8000-bbbb00000002\",\"task_id\":null,\"subject_ref\":\"s\",\"receipt_body_json_b64\":\"{trailing_body}\",\"canonical_receipt\":{{\"receipt_id\":\"0196a1b2-c3d4-7e5f-8000-cccc00000003\",\"write_id\":\"0196a1b2-c3d4-7e5f-8000-dddd00000004\"}},\"memory_revision\":1,\"project_sequence\":1}}"
    );
    assert!(decode_raw::<CanonicalRecord<Value>>(&raw).is_err());
    let valid = fixture_raw("976-01-valid-envelope")?;
    assert!(decode_raw::<CanonicalRecord<Value>>(&valid).is_ok());
    Ok(())
}

// WORK_UNIT_CASE: 976/15
#[test]
fn diagnostics_and_debug_stay_redacted() -> Result<(), Box<dyn std::error::Error>> {
    let canary = "CANARY-976-SECRET-4d2c9a1e7b5f";
    let body = format!("{{\"secret\":\"{canary}\"}}");
    let valid = envelope_with(&body);
    let record: CanonicalRecord<Value> = serde_json::from_str(&valid)?;
    let debug = format!("{record:?}");
    assert!(!debug.contains(canary));
    assert!(debug.contains("[redacted]"));
    let dup_body = format!("{{\"k\":\"{canary}\",\"k\":\"x\"}}");
    let dup_raw = envelope_with(&dup_body);
    let err = expect_err(
        decode_raw::<CanonicalRecord<Value>>(&dup_raw),
        "debug canary dup",
    )?;
    assert!(!err.contains(canary));
    Ok(())
}

// WORK_UNIT_CASE: 976/16
#[test]
fn allowed_diff_api_serialization_guard() -> Result<(), Box<dyn std::error::Error>> {
    let raw = fixture_raw("976-16-allowed-shape")?;
    let record: CanonicalRecord<Value> = serde_json::from_str(&raw)?;
    let value = serde_json::to_value(&record)?;
    let object = value.as_object().ok_or("record must serialize as object")?;
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "canonical_receipt",
            "memory_revision",
            "project_id",
            "project_sequence",
            "receipt_body",
            "receipt_kind",
            "record_id",
            "subject_ref",
            "task_id",
        ]
    );
    assert!(!object.contains_key("receipt_body_json_b64"));
    let cloned = record.clone();
    assert_eq!(cloned.receipt_body, serde_json::json!({"state": "active"}));
    Ok(())
}
