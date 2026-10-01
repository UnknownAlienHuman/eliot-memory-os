//! Issue #939 (`F-DENY-T10`): `EvalIntegrityFingerprintSet` is a closed
//! protected nested decoder. Unknown identity dimensions must be refused
//! at deserialization so they can never be silently discarded before the
//! `is_stale_against` exact-equality check, while historic payloads keep
//! their fail-closed defaults and accepted bytes.

#![allow(clippy::expect_used)]

use eliot_types::{EvalBaseline, EvalCaseResult, EvalIntegrityFingerprintSet};
use serde_json::Value;

fn corpus() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
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

/// All nine known identity dimensions, as a wire payload that carries none
/// outside the closed set. Used as the equality target of the nested
/// positive cases: a decoded nested set must be indistinguishable from the
/// owner-constructed one, or `is_stale_against` would mark current evidence
/// stale for a reason that has nothing to do with identity drift.
fn current_identity() -> EvalIntegrityFingerprintSet {
    EvalIntegrityFingerprintSet {
        harness_fingerprint: "eliot-engine-eval-case-schema".to_owned(),
        evaluator_fingerprint: "eliot_engine::eval::EvalMeasurementService".to_owned(),
        environment_fingerprint: "not-captured:structural-evaluator-process".to_owned(),
        actual_route: "eliot_engine::eval::evaluate_case".to_owned(),
        requested_route: "runtime artifact/effect observation".to_owned(),
        acceptance_relation: "required criterion matches a measurement result".to_owned(),
        oracle_owner: "eliot_engine::eval::EvalMeasurementService".to_owned(),
        oracle_version: "0.1.0".to_owned(),
        product_identity:
            "eliot-memory-os/eliot-engine-eval:product:01920000-0000-7000-8000-000000000001"
                .to_owned(),
    }
}

#[test]
fn nine_known_fields_decode() {
    let decoded: EvalIntegrityFingerprintSet =
        serde_json::from_value(case("nine_field_accept")).expect("nine known fields must decode");
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
        product_identity:
            "eliot-memory-os/eliot-engine-eval:product:01920000-0000-7000-8000-000000000001"
                .to_owned(),
        ..decoded.clone()
    };
    assert!(
        decoded.is_stale_against(&current),
        "historic empty defaults must compare stale against current nonempty identity"
    );
}

// WORK_UNIT_CASE: 939/3
#[test]
fn nested_case_result_nine_fields_decode_and_match_current_identity() {
    let decoded: EvalCaseResult =
        serde_json::from_value(case("nested_case_result_nine_field_accept"))
            .expect("a case result carrying all nine known identity fields must decode");
    let recorded = decoded
        .integrity_fingerprints
        .expect("this case result retains identity fingerprints");
    assert_eq!(
        recorded,
        current_identity(),
        "the closed nested decoder must preserve every known identity dimension"
    );
    assert!(
        !recorded.is_stale_against(&current_identity()),
        "a case result recorded under current identity must not be stale-marked"
    );
}

// WORK_UNIT_CASE: 939/4
#[test]
fn nested_case_result_unknown_identity_dimension_refused() {
    assert!(
        serde_json::from_value::<EvalCaseResult>(case(
            "nested_case_result_unknown_identity_dimension_refuse"
        ))
        .is_err(),
        "an unrecognized nested identity dimension must refuse the whole case result \
         instead of being discarded before the freshness check"
    );
}

// WORK_UNIT_CASE: 939/5
#[test]
fn nested_baseline_nine_fields_decode_and_match_current_identity() {
    let decoded: EvalBaseline =
        serde_json::from_value(case("nested_baseline_nine_field_accept"))
            .expect("a baseline carrying all nine known identity fields must decode");
    let recorded = decoded
        .integrity_fingerprints
        .expect("this baseline retains identity fingerprints");
    assert_eq!(
        recorded,
        current_identity(),
        "the closed nested decoder must preserve every known identity dimension"
    );
    assert!(
        !recorded.is_stale_against(&current_identity()),
        "a baseline approved under current identity must not be stale-marked"
    );
}

// WORK_UNIT_CASE: 939/6
#[test]
fn nested_baseline_unknown_identity_dimension_refused() {
    assert!(
        serde_json::from_value::<EvalBaseline>(case(
            "nested_baseline_unknown_identity_dimension_refuse"
        ))
        .is_err(),
        "an unrecognized nested identity dimension must refuse the whole baseline \
         instead of being discarded before the freshness check"
    );
}
