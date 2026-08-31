use eliot_agent_contracts::{
    WorkLeaseIssuanceDisposition, WorkLeaseIssuanceError, WorkLeaseIssuanceProvenance,
    WorkLeaseIssuanceResult,
};

fn assert_public_contract_type<T>() {}

#[test]
fn provider_neutral_agent_contract_package_owns_work_lease_issuance() {
    assert_public_contract_type::<WorkLeaseIssuanceDisposition>();
    assert_public_contract_type::<WorkLeaseIssuanceError>();
    assert_public_contract_type::<WorkLeaseIssuanceProvenance>();
    assert_public_contract_type::<WorkLeaseIssuanceResult>();
}

#[test]
fn provider_neutral_issuance_owner_does_not_depend_on_legacy_domain_types() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("eliot-types"),
        "eliot-agent-contracts must not acquire the legacy eliot-types dependency while taking ownership of WorkLease issuance"
    );
}
