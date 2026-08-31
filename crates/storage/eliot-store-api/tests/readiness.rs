use eliot_store_api::{ReadinessReceipt, ReadinessStatus, StoreResponse, StoreWireError};

const GENERATION_MISMATCH: &str =
    "ready readiness requires matching expected and observed schema generations";

fn mismatched_ready() -> ReadinessReceipt {
    ReadinessReceipt {
        status: ReadinessStatus::Ready,
        expected_generation: Some("schema-v2".to_owned()),
        observed_generation: Some("schema-v1".to_owned()),
    }
}

fn assert_generation_mismatch(result: Result<(), StoreWireError>) {
    assert_eq!(
        result,
        Err(StoreWireError::Invalid(GENERATION_MISMATCH.to_owned()))
    );
}

#[test]
fn ready_constructor_binds_one_exact_generation() {
    let receipt = ReadinessReceipt::ready("schema-v2".to_owned());
    assert_eq!(receipt.expected_generation.as_deref(), Some("schema-v2"));
    assert_eq!(receipt.observed_generation.as_deref(), Some("schema-v2"));
    assert!(receipt.validate().is_ok());
}

#[test]
fn ready_rejects_different_expected_and_observed_generations() {
    assert_generation_mismatch(mismatched_ready().validate());
}

#[test]
fn mismatched_ready_wire_decodes_as_data_but_fails_contract_validation() {
    let wire = serde_json::json!({
        "status": "ready",
        "expected_generation": "schema-v2",
        "observed_generation": "schema-v1"
    });
    let receipt: ReadinessReceipt =
        serde_json::from_value(wire).expect("shape is decodable for explicit validation");
    assert_generation_mismatch(receipt.validate());
}

#[test]
fn store_response_cannot_publish_mismatched_ready() {
    let response = StoreResponse::Readiness {
        receipt: mismatched_ready(),
    };
    assert_generation_mismatch(response.validate());
}

#[test]
fn migration_required_preserves_an_observed_generation_mismatch() {
    let receipt = ReadinessReceipt::migration_required(
        "schema-v2".to_owned(),
        Some("schema-v1".to_owned()),
    );
    assert!(receipt.validate().is_ok());
}

#[test]
fn migration_required_allows_an_unobserved_generation() {
    let receipt = ReadinessReceipt::migration_required("schema-v2".to_owned(), None);
    assert!(receipt.validate().is_ok());
}

#[test]
fn unavailable_cannot_carry_schema_generation_claims() {
    let receipt = ReadinessReceipt {
        status: ReadinessStatus::Unavailable,
        expected_generation: Some("schema-v2".to_owned()),
        observed_generation: None,
    };
    assert!(matches!(receipt.validate(), Err(StoreWireError::Invalid(_))));
}
