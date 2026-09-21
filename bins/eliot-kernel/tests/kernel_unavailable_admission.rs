#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Smallest acceptance proof for issue #1972 (I1.13 Kernel unavailability).
//!
//! Proves only what the acceptance criteria name: admission denial while the
//! Kernel is unavailable, the restricted Recovery View boundary, the
//! external-tool non-claim, and broker-loss route scoping. No fixture matrix.

use eliot_kernel::KernelComposition;
use eliot_kernel::kernel_unavailability::{
    AdmissionDenial, BrokerAvailability, BrokerRouteDecision, ExternalToolStatus,
    KernelAvailability, RecoveryView, admit_canonical_write, admit_external_material_authority,
    admit_lease, admit_machine_canonical_operation, admit_new_session, decide_broker_route,
    report_external_tool_status,
};

// WORK_UNIT_CASE: 1972/1 — new authorities are denied while Kernel is unavailable.
#[test]
fn kernel_unavailable_denies_all_new_authorities() {
    let kernel = KernelAvailability::Unavailable;
    assert_eq!(
        admit_new_session(kernel),
        Err(AdmissionDenial::KernelUnavailable)
    );
    assert_eq!(admit_lease(kernel), Err(AdmissionDenial::KernelUnavailable));
    assert_eq!(
        admit_canonical_write(kernel),
        Err(AdmissionDenial::KernelUnavailable)
    );
    assert_eq!(
        admit_external_material_authority(kernel),
        Err(AdmissionDenial::KernelUnavailable)
    );
}

// WORK_UNIT_CASE: 1972/2 — Recovery View stays reachable with only allowed categories.
#[test]
fn recovery_view_contains_only_allowed_status_categories() {
    let view = RecoveryView::new(
        serde_json::json!({"artifact_digest": "abc"}),
        serde_json::json!({"generation": 3}),
        serde_json::json!({"records": 1}),
        serde_json::json!({"incidents": []}),
    );
    let projected = KernelComposition::recovery_view_response(&view);
    let object = projected.as_object().expect("recovery view is an object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["build", "generation", "incident", "ors"]);

    let deferral = KernelComposition::deferred_semantic_recovery(KernelAvailability::Unavailable);
    assert_eq!(
        deferral.reason,
        "semantic task recovery deferred pending canonical access"
    );
}

// WORK_UNIT_CASE: 1972/3 — running external tools are not claimed stopped
// without observed enforcement.
#[test]
fn external_tool_without_evidence_is_enforcement_unobserved() {
    assert_eq!(
        report_external_tool_status(false),
        ExternalToolStatus::EnforcementUnobserved
    );
    assert_eq!(
        report_external_tool_status(false).to_string(),
        "enforcement unobserved"
    );
    assert_eq!(
        report_external_tool_status(true),
        ExternalToolStatus::EnforcementObservedStopped
    );
}

// WORK_UNIT_CASE: 1972/4 — broker loss defers only interactive-user work.
#[test]
fn broker_unavailable_keeps_machine_work_admissible() {
    let broker = BrokerAvailability::Unavailable;
    assert_eq!(
        admit_machine_canonical_operation(KernelAvailability::Available, broker),
        Ok(BrokerRouteDecision::Admit)
    );
    assert_eq!(
        decide_broker_route(broker, "interactive_user:sid-1", false),
        BrokerRouteDecision::Defer
    );
    assert_eq!(
        decide_broker_route(broker, "interactive_user:sid-1", true),
        BrokerRouteDecision::Reconcile
    );
    assert_eq!(
        decide_broker_route(broker, "daemon", false),
        BrokerRouteDecision::Admit
    );
}
