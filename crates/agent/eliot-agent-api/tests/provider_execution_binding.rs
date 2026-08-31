use std::error::Error;

use eliot_agent_api::{
    AgentAttemptId, ProviderExecutionBinding, ProviderExecutionUnitId, ProviderSessionLocator,
};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error>>;

const BINDING_SCHEMA_VERSION: &str = "a01-provider-execution-binding/v1";

fn route_wire() -> Value {
    json!({
        "host_family": "codex",
        "adapter": "eliot-agent-codex",
        "protocol_transport": "app-server+stdio/jsonl",
        "runtime_hash": "runtime-v1",
        "adapter_hash": "adapter-v1",
        "provider": "provider-a",
        "model": "model-a",
        "auth_billing": "account-a",
        "serializer_hash": "serializer-v1",
        "tool_semantics_hash": "tools-v1",
        "reasoning_mode": "visible",
        "continuation_behavior": "native-resume",
        "feature_flags_hash": "features-v1"
    })
}

fn binding_wire(attempt_id: &str, execution_unit: &str) -> Value {
    json!({
        "schema_version": BINDING_SCHEMA_VERSION,
        "attempt_id": attempt_id,
        "route": route_wire(),
        "runtime_generation": 7,
        "provider_session": "thread-1",
        "execution_unit": execution_unit,
        "state_fence": {
            "authority_epoch": 3,
            "resource_generation": 11,
            "task_revision": 5,
            "policy_revision": 2,
            "integration_revision": 4
        }
    })
}

#[test]
fn one_attempt_binds_exactly_one_provider_execution_unit() -> TestResult {
    let binding: ProviderExecutionBinding =
        serde_json::from_value(binding_wire("attempt-a", "turn-a"))?;

    binding.validate()?;
    assert_eq!(binding.attempt_id, AgentAttemptId::new("attempt-a")?);
    assert_eq!(
        binding.provider_session,
        ProviderSessionLocator::new("thread-1")?
    );
    assert_eq!(
        binding.execution_unit,
        ProviderExecutionUnitId::new("turn-a")?
    );
    assert_eq!(binding.runtime_generation.value(), 7);
    assert_eq!(binding.state_fence.authority_epoch.value(), 3);
    assert_eq!(binding.state_fence.resource_generation.value(), 11);

    let roundtrip: ProviderExecutionBinding =
        serde_json::from_value(serde_json::to_value(&binding)?)?;
    assert_eq!(roundtrip, binding);
    Ok(())
}

#[test]
fn missing_or_blank_execution_unit_is_rejected() -> TestResult {
    let mut missing = binding_wire("attempt-a", "turn-a");
    missing
        .as_object_mut()
        .expect("binding fixture is an object")
        .remove("execution_unit");
    assert!(serde_json::from_value::<ProviderExecutionBinding>(missing).is_err());

    let blank: ProviderExecutionBinding =
        serde_json::from_value(binding_wire("attempt-a", "   "))?;
    assert!(blank.validate().is_err());
    Ok(())
}

#[test]
fn open_or_multi_turn_set_is_not_a_v1_binding() {
    let mut multi = binding_wire("attempt-a", "turn-a");
    let object = multi
        .as_object_mut()
        .expect("binding fixture is an object");
    object.remove("execution_unit");
    object.insert("execution_units".to_owned(), json!(["turn-a", "turn-b"]));

    assert!(serde_json::from_value::<ProviderExecutionBinding>(multi).is_err());
}

#[test]
fn wrong_schema_or_unknown_fields_are_rejected() {
    let mut wrong_schema = binding_wire("attempt-a", "turn-a");
    wrong_schema["schema_version"] = json!("a01-provider-execution-binding/v2");
    assert!(serde_json::from_value::<ProviderExecutionBinding>(wrong_schema).is_err());

    let mut unknown = binding_wire("attempt-a", "turn-a");
    unknown["ambient_current_attempt"] = json!(true);
    assert!(serde_json::from_value::<ProviderExecutionBinding>(unknown).is_err());
}

#[test]
fn provider_session_locator_is_not_an_eliot_session_id() -> TestResult {
    let binding: ProviderExecutionBinding =
        serde_json::from_value(binding_wire("attempt-a", "turn-a"))?;
    let provider_locator: &ProviderSessionLocator = &binding.provider_session;

    assert_eq!(provider_locator.as_str(), "thread-1");
    Ok(())
}
