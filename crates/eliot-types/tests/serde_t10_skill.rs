//! Issue #939 (`F-DENY-T10`): `EvalIntegrityFingerprintSet` is a closed
//! protected nested decoder. Unknown identity dimensions must be refused
//! at deserialization so they can never be silently discarded before the
//! `is_stale_against` exact-equality check, while historic payloads keep
//! their fail-closed defaults and accepted bytes.
//!
//! Audit comment 5900564590 requirement 3: the three cases below decoded the
//! fingerprint struct DIRECTLY, which never proves the production decode paths.
//! `EvalCaseResult.integrity_fingerprints` and `EvalBaseline.integrity_fingerprints`
//! embed the set, so erasure happened through those two owners. The cases at
//! the end of this file therefore decode whole owner records and each owner
//! path is exercised with a payload pair that differs ONLY in the unsupported
//! nested member, so a refusal cannot be a self-comparison of the struct
//! against itself.

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

/// The refusal message of one decode attempt. A bare `is_err()` would be
/// satisfied by any failure in the whole record, so the caller also reads the
/// message to bind the refusal to the nested member it names.
fn refusal_message<T: serde::de::DeserializeOwned>(payload: Value) -> String {
    match serde_json::from_value::<T>(payload) {
        Ok(_) => panic!("decode must be refused"),
        Err(error) => error.to_string(),
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

// WORK_UNIT_CASE: 939/03 — audit comment 5900564590 requirement 3. The three
// cases above build or decode the fingerprint struct on its own, so they cannot
// see the two production owners that embed it. These three decode whole owner
// records. Each owner is exercised with a positive/negative payload pair that
// differs ONLY in the unsupported nested member (`evaluator_tier`), so the
// refusal is attributable to that member and not to any other field of the
// record.

#[test]
fn known_nested_fingerprints_decode_through_eval_case_result_and_baseline() {
    let result: EvalCaseResult = serde_json::from_value(case("case_result_nested_known_accept"))
        .expect("a fully known nested fingerprint set must decode through EvalCaseResult");
    assert_eq!(
        result.result_id, "eval-case-result-01920000-0000-7000-8000-000000000002",
        "the record itself must decode, so the positive case proves the owner path accepts it"
    );
    let result_fingerprints = result
        .integrity_fingerprints
        .as_ref()
        .expect("the known nested fingerprint set must survive the EvalCaseResult decode");
    assert_eq!(
        result_fingerprints.harness_fingerprint,
        "eliot-engine-eval-case-schema"
    );
    assert_eq!(result_fingerprints.oracle_version, "0.1.0");
    assert_eq!(
        result_fingerprints.product_identity,
        "eliot-memory-os/eliot-engine-eval:product:01920000-0000-7000-8000-000000000001"
    );

    let baseline: EvalBaseline = serde_json::from_value(case("baseline_nested_known_accept"))
        .expect("a fully known nested fingerprint set must decode through EvalBaseline");
    assert_eq!(
        baseline.baseline_id, "eval-baseline-01920000-0000-7000-8000-000000000004",
        "the record itself must decode, so the positive case proves the owner path accepts it"
    );
    let baseline_fingerprints = baseline
        .integrity_fingerprints
        .as_ref()
        .expect("the known nested fingerprint set must survive the EvalBaseline decode");
    assert_eq!(
        baseline_fingerprints.harness_fingerprint,
        "eliot-engine-eval-case-schema"
    );
    assert_eq!(baseline_fingerprints.oracle_version, "0.1.0");
    assert_eq!(
        baseline_fingerprints.product_identity,
        "eliot-memory-os/eliot-engine-eval:product:01920000-0000-7000-8000-000000000001"
    );
}

#[test]
fn nested_unknown_identity_dimension_refused_through_eval_case_result() {
    let refusal = refusal_message::<EvalCaseResult>(case("case_result_nested_unknown_refuse"));
    assert!(
        refusal.contains("unknown field") && refusal.contains("`evaluator_tier`"),
        "EvalCaseResult must refuse the unsupported nested identity member and name it; \
         a refusal for any other field would not close nested-field erasure: {refusal}"
    );
}

#[test]
fn nested_unknown_identity_dimension_refused_through_eval_baseline() {
    let refusal = refusal_message::<EvalBaseline>(case("baseline_nested_unknown_refuse"));
    assert!(
        refusal.contains("unknown field") && refusal.contains("`evaluator_tier`"),
        "EvalBaseline must refuse the unsupported nested identity member and name it; \
         a refusal for any other field would not close nested-field erasure: {refusal}"
    );
}
