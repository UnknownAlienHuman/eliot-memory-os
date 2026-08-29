use eliot_context_contracts::{
    ContextContractError, ContextProviderClass, ContextProviderDescriptor,
    ContextProviderProjectionRequest, ContextProviderRegistrySnapshot, ContextRole,
    ExpectedContextProvider, ExpectedContextProviderSet, ExpectedProviderSetDisposition,
    ProviderAvailabilityClass, ProviderId, ProviderRequirement, context_provider_registry_digest,
    expected_provider_set_digest, validate_context_provider_registry,
    validate_context_provider_request, validate_expected_provider_set,
};
use eliot_contracts::{
    AuthorityEpoch, ContractId, ContractIdentity, ContractVersion, RequestId, ResourceGeneration,
    StateFence, TaskRevision,
};

fn fence(generation: u64) -> StateFence {
    StateFence::new(
        AuthorityEpoch::genesis(),
        ResourceGeneration::new(generation).expect("generation"),
    )
}

fn provider_id(value: &str) -> ProviderId {
    ProviderId::new(value).expect("provider")
}

fn contract(name: &str) -> ContractIdentity {
    ContractIdentity {
        name: ContractId::new(name).expect("contract"),
        version: ContractVersion::new(1, 0, 0),
        shape_sha256: "a".repeat(64),
    }
}

fn descriptor(id: &str, roles: Vec<ContextRole>) -> ContextProviderDescriptor {
    ContextProviderDescriptor {
        provider_id: provider_id(id),
        class: if id == "memory" {
            ContextProviderClass::Memory
        } else {
            ContextProviderClass::GoalAcceptance
        },
        generation: "generation-1".to_owned(),
        contract_identity: contract(&format!("provider-{id}")),
        supported_roles: roles,
        availability: ProviderAvailabilityClass::Available,
        state_fence: fence(1),
    }
}

#[test]
fn registry_digest_is_order_independent() {
    let build = |providers| {
        let mut value = ContextProviderRegistrySnapshot {
            registry_revision: TaskRevision::genesis(),
            scope_id: "scope-1".to_owned(),
            state_fence: fence(1),
            providers,
            snapshot_sha256: String::new(),
        };
        value.snapshot_sha256 = context_provider_registry_digest(&value).expect("digest");
        value
    };
    let left = build(vec![
        descriptor("memory", vec![ContextRole::Safety, ContextRole::Evidence]),
        descriptor("goal", vec![ContextRole::Goal]),
    ]);
    let right = build(vec![
        descriptor("goal", vec![ContextRole::Goal]),
        descriptor("memory", vec![ContextRole::Evidence, ContextRole::Safety]),
    ]);
    assert_eq!(left.snapshot_sha256, right.snapshot_sha256);
    validate_context_provider_registry(&left).expect("left");
    validate_context_provider_registry(&right).expect("right");
}

#[test]
fn mandatory_unavailable_provider_blocks_expected_set() {
    let mut value = ExpectedContextProviderSet {
        registry_snapshot_sha256: "b".repeat(64),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(1),
        providers: vec![ExpectedContextProvider {
            provider_id: provider_id("memory"),
            class: ContextProviderClass::Memory,
            generation: "generation-1".to_owned(),
            contract_shape_sha256: "a".repeat(64),
            requirement: ProviderRequirement::Mandatory,
            supported_roles: vec![ContextRole::Evidence, ContextRole::Safety],
            required_roles: vec![ContextRole::Evidence],
            availability: ProviderAvailabilityClass::Unavailable,
        }],
        disposition: ExpectedProviderSetDisposition::Blocked,
        set_sha256: String::new(),
    };
    value.set_sha256 = expected_provider_set_digest(&value).expect("digest");
    validate_expected_provider_set(&value).expect("explicit blocked set");
}

#[test]
fn disposition_cannot_hide_unavailability() {
    let mut value = ExpectedContextProviderSet {
        registry_snapshot_sha256: "b".repeat(64),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(1),
        providers: vec![ExpectedContextProvider {
            provider_id: provider_id("memory"),
            class: ContextProviderClass::Memory,
            generation: "generation-1".to_owned(),
            contract_shape_sha256: "a".repeat(64),
            requirement: ProviderRequirement::Mandatory,
            supported_roles: vec![ContextRole::Evidence],
            required_roles: vec![ContextRole::Evidence],
            availability: ProviderAvailabilityClass::Unavailable,
        }],
        disposition: ExpectedProviderSetDisposition::Complete,
        set_sha256: String::new(),
    };
    value.set_sha256 = expected_provider_set_digest(&value).expect("digest");
    assert_eq!(
        validate_expected_provider_set(&value),
        Err(ContextContractError::DispositionInvalid)
    );
}

#[test]
fn generic_request_rejects_role_overclaim() {
    let request = ContextProviderProjectionRequest {
        request_id: RequestId::new("request-1").expect("id"),
        provider: descriptor("memory", vec![ContextRole::Evidence]),
        expected_provider_set_sha256: "b".repeat(64),
        scope_id: "scope-1".to_owned(),
        task_id: None,
        state_fence: fence(1),
        requested_roles: vec![ContextRole::Evidence, ContextRole::Goal],
        safety_floor_roles: vec![ContextRole::Evidence],
        maximum_atoms: 10,
        maximum_rendered_bytes: 1_024,
    };
    assert_eq!(
        validate_context_provider_request(&request),
        Err(ContextContractError::RoleUnsupported(ContextRole::Goal))
    );
}
