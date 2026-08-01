use eliot_types::{AgentHostId, ProviderDeclaredBudget, ProviderRoutePolicy};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn same_route_and_budget_produce_byte_identical_policy() -> TestResult {
    let budget =
        ProviderDeclaredBudget::new(120_000, 1_048_576).with_idle_output_deadline_ms(Some(30_000));
    let first = ProviderRoutePolicy::for_route(
        AgentHostId::Antigravity,
        "external-agent-smoke",
        budget.clone(),
    );
    let second =
        ProviderRoutePolicy::for_route(AgentHostId::Antigravity, "external-agent-smoke", budget);

    assert_eq!(first, second);
    assert_eq!(serde_json::to_vec(&first)?, serde_json::to_vec(&second)?);
    assert_eq!(first.policy_id(), second.policy_id());
    assert_eq!(first.policy_hash_blake3(), second.policy_hash_blake3());
    assert_eq!(first.policy_hash_blake3().len(), 64);
    Ok(())
}

#[test]
fn current_cli_route_has_one_bounded_timeout_contract() {
    let policy = ProviderRoutePolicy::for_route(
        AgentHostId::Claude,
        "external-agent-smoke",
        ProviderDeclaredBudget::new(120_000, 1_048_576),
    );
    let timeout = policy.timeout_profile();

    assert_eq!(timeout.profile_id(), policy.policy_id());
    assert_eq!(timeout.spawn_deadline_ms(), Some(5_000));
    assert_eq!(timeout.dispatch_ack_deadline_ms(), None);
    assert_eq!(timeout.first_output_deadline_ms(), Some(120_000));
    assert_eq!(timeout.absolute_runtime_deadline_ms(), 120_000);
    assert_eq!(policy.output_limit_bytes(), 1_048_576);
    assert!(policy.incremental_output_supported());
    assert!(!policy.status_lookup_supported());
}
