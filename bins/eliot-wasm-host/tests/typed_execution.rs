//! Focused typed execution tests for issue #758 (owner order: no matrices).

use eliot_wasm_host::{
    TypedExecutionError, TypedWorld, default_experimental_limits, execute_describe_experimental,
    execute_governed_refusal,
};
use eliot_wasm_runtime::Sha256Digest;

#[test]
fn governed_refusal_is_fail_closed() {
    match execute_governed_refusal() {
        Err(TypedExecutionError::GovernedAdmissionRequired) => {}
        Err(other) => panic!("wrong governed denial: {other}"),
        Ok(()) => panic!("governed execution must refuse without Kernel admission"),
    }
    let display = match execute_governed_refusal() {
        Err(error) => error.to_string(),
        Ok(()) => panic!("governed execution must refuse without Kernel admission"),
    };
    assert_eq!(display, "KERNEL_ADMISSION_REQUIRED");
}

#[test]
fn typed_rejects_legacy_component_without_promotion() -> Result<(), String> {
    // The checked-in legacy `run` component is real engine input: it
    // compiles and reports zero imports, but its `run` export must never
    // satisfy a typed world selection or auto-upgrade to typed execution.
    let artifact =
        wat::parse_file("tests/fixtures/guest.wat").map_err(|error| error.to_string())?;
    let digest = Sha256Digest::of_bytes(&artifact);
    let limits = default_experimental_limits(digest);
    match execute_describe_experimental(TypedWorld::ContextAdmission, &artifact, &limits) {
        Err(TypedExecutionError::LegacyMismatch) => Ok(()),
        Err(other) => Err(format!("wrong denial: {other}")),
        Ok(_) => Err("legacy component must not execute as typed".to_owned()),
    }
}
