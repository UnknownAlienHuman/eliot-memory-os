//! Issue #939 (`F-DENY-T10`): `EvalIntegrityFingerprintSet` is a closed
//! protected nested decoder. Unknown identity dimensions must be refused
//! at deserialization so they can never be silently discarded before the
//! `is_stale_against` exact-equality check, while historic payloads keep
//! their fail-closed defaults and accepted bytes.

#![allow(clippy::expect_used)]

use eliot_types::EvalIntegrityFingerprintSet;
use serde_json::Value;

fn corpus() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("serde_t10_skill_eval.json");
    let text = std::fs::read_to_string(&path).expect("serde_t10_skill_eval.json must exist");
    serde_json::from_str(&text).expect("serde_t10_skill_eval.json must be valid JSON")
}

fn case(name: &str) -> Value {
    corpus()
        .get(name)
        .unwrap_or_else(|| panic!("corpus must contain case {name}"))
        .clone()
}

#[test]
fn nine_known_fields_decode() {
    let decoded: EvalIntegrityFingerprintSet = serde_json::from_value(case("nine_field_accept"))
        .expect("nine known fields must decode");
    assert_eq!(decoded.harness_fingerprint, "eliot-engine-eval-case-schema");
    assert_eq!(decoded.oracle_version, "0.1.0");
    assert_eq!(
        decoded.product_identity,
        "eliot-memory-os/eliot-engine-eval:product:01920000-0000-7000-8000-000000000001"
    );
    assert!(
        !decoded.is_stale_against(&decoded),
        "identical fingerprint sets must compare fresh"
    );
}

#[test]
fn unknown_identity_dimension_refused() {
    assert!(
        serde_json::from_value::<EvalIntegrityFingerprintSet>(case(
            "unknown_identity_dimension_refuse"
        ))
        .is_err(),
        "unknown identity dimension must be refused, never silently dropped"
    );
}

#[test]
fn missing_version_and_product_decode_empty_and_compare_stale() {
    let decoded: EvalIntegrityFingerprintSet =
        serde_json::from_value(case("missing_defaults_fail_closed"))
            .expect("historic payload without oracle_version/product_identity must decode");
    assert_eq!(decoded.oracle_version, "");
    assert_eq!(decoded.product_identity, "");
    let current = EvalIntegrityFingerprintSet {
        oracle_version: "0.1.0".to_owned(),
        product_identity: "eliot-memory-os/eliot-engine-eval:product:01920000-0000-7000-8000-000000000001"
            .to_owned(),
        ..decoded.clone()
    };
    assert!(
        decoded.is_stale_against(&current),
        "historic empty defaults must compare stale against current nonempty identity"
    );
}
