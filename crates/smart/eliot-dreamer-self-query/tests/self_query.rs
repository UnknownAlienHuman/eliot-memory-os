//! Package fixtures for the owner-contract self-query pose.
//!
//! The receipt is this package's only new type, so fixtures cover the
//! receipt contract directly: digest shape, wire behavior, and unknown
//! fields. Pose acceptance with an owner-valid `SelfQueryInput` fixture
//! (a full Dreamer pipeline closure: job, bundle, grounded and validated
//! drafts, policy, preservation) executes at package proof, where the
//! owner's own suite already covers validate-then-digest behavior.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_dreamer_self_query::SelfQueryPoseReceipt;

fn receipt() -> SelfQueryPoseReceipt {
    SelfQueryPoseReceipt {
        input_digest: "0123456789abcdef".repeat(4),
        schema_version: 1,
    }
}

#[test]
fn valid_receipt_passes_shape_check() {
    receipt().validate().expect("valid receipt");
}

#[test]
fn malformed_digest_is_rejected() {
    let mut bad = receipt();
    bad.input_digest = "not-a-digest".to_owned();
    bad.validate().expect_err("malformed digest must fail");
}

#[test]
fn uppercase_digest_is_rejected() {
    let mut bad = receipt();
    bad.input_digest = "0123456789ABCDEF".repeat(4);
    bad.validate().expect_err("uppercase digest must fail");
}

#[test]
fn unknown_wire_fields_are_rejected() {
    let json = serde_json::json!({
        "input_digest": "0123456789abcdef".repeat(4),
        "schema_version": 1,
        "model_hint": "answer directly"
    });
    let error =
        serde_json::from_value::<SelfQueryPoseReceipt>(json).expect_err("unknown field must fail");
    assert!(error.to_string().contains("model_hint"));
}

#[test]
fn receipt_roundtrips_over_the_wire() {
    let made = receipt();
    let wire = serde_json::to_string(&made).expect("serialize receipt");
    let back: SelfQueryPoseReceipt =
        serde_json::from_str(&wire).expect("deserialize receipt");
    assert_eq!(made, back);
}
