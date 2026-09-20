//! Issue #1911 minimal contract proof: declared external-adapter
//! operations run through the governed action envelope before any adapter.
//!
//! Proves only the acceptance: a Material op without a valid
//! authority-bound envelope is rejected pre-adapter with the standardized
//! reason, preserved state, retry status, required authority/repair, and
//! allowed next action; a valid envelope records an effect linked to the
//! State Fence and verifier, and an unmet verifier never completes.

use std::sync::Mutex;

use eliot_native_worker::governed_action::{
    ActionEnvelope, EXTERNAL_ADAPTER_OPS, FinishState, ImpactClass, derive_impact,
    finish_for_verdict, is_external_adapter_op, record_effect, require_governed_op,
    run_governed_external_op,
};

fn fence() -> serde_json::Value {
    serde_json::json!({
        "epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 1},
        "generation": 1,
        "fence": "fence-1911-1",
    })
}

fn epoch() -> serde_json::Value {
    serde_json::json!({
        "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
        "sequence": 1,
    })
}

fn valid_envelope(operation: &str) -> ActionEnvelope {
    ActionEnvelope {
        operation: operation.to_owned(),
        intent: format!("execute governed {operation}"),
        scope_ref: "scope-1911".to_owned(),
        preconditions: "claim admitted; fence live".to_owned(),
        expected_effect: format!("bounded {operation} effect with receipt"),
        invariants: "no ambient effects; fence unchanged".to_owned(),
        known_failures: "stale fence; revoked join".to_owned(),
        rollback_or_compensation: "reconcile retained receipt; no second start".to_owned(),
        verifier: "verifier-1911".to_owned(),
        stop_condition: "stop on fence mismatch or verifier refusal".to_owned(),
        state_fence: fence(),
        authority_epoch: epoch(),
        tool_profile: operation.to_owned(),
        affected_resources: vec!["external-adapter".to_owned()],
        applicable_authority: format!("kernel-authority-for-{operation}"),
    }
}

#[test]
fn material_op_without_envelope_is_rejected_pre_adapter_with_full_repair_shape() {
    for operation in EXTERNAL_ADAPTER_OPS {
        assert!(is_external_adapter_op(operation));
        let invokes = Mutex::new(0_usize);
        let outcome = run_governed_external_op(operation, None, |_validated| {
            *invokes.lock().unwrap_or_else(|error| {
                panic!("1911 fixture lock failed: {error:?}");
            }) += 1;
            "adapter-effect"
        });
        let Err(rejection) = outcome else {
            panic!("{operation} without an envelope must be rejected");
        };
        assert_eq!(
            *invokes.lock().unwrap_or_else(|error| {
                panic!("1911 fixture lock failed: {error:?}");
            }),
            0,
            "{operation} must not invoke the adapter on rejection"
        );
        assert_eq!(rejection.operation, operation);
        assert!(!rejection.reason.trim().is_empty());
        assert!(!rejection.preserved_state.trim().is_empty());
        assert!(rejection.retryable);
        assert!(!rejection.retry_status.trim().is_empty());
        assert!(!rejection.required_authority.trim().is_empty());
        assert!(!rejection.required_repair.trim().is_empty());
        assert!(!rejection.allowed_next_action.trim().is_empty());
        // The direct require path agrees: no envelope, no adapter.
        assert!(require_governed_op(None, operation).is_err());
    }
}

#[test]
fn valid_envelope_records_fence_bound_effect_and_unmet_verifier_never_completes() {
    let envelope = valid_envelope("start_claimed");
    assert_eq!(
        derive_impact(envelope.tool_profile.as_str(), &envelope.affected_resources),
        ImpactClass::Material
    );
    let invokes = Mutex::new(0_usize);
    let (validated, adapter_output) =
        match run_governed_external_op("start_claimed", Some(&envelope), |validated| {
            *invokes.lock().unwrap_or_else(|error| {
                panic!("1911 fixture lock failed: {error:?}");
            }) += 1;
            format!("effect-for-{}", validated.operation)
        }) {
            Ok(ok) => ok,
            Err(rejection) => panic!("valid envelope must admit: {rejection:?}"),
        };
    assert_eq!(
        *invokes.lock().unwrap_or_else(|error| {
            panic!("1911 fixture lock failed: {error:?}");
        }),
        1
    );
    assert_eq!(adapter_output, "effect-for-start_claimed");
    let effect = record_effect(&validated, &adapter_output);
    assert_eq!(effect.state_fence, fence());
    assert_eq!(effect.verifier, "verifier-1911");
    assert_eq!(effect.operation, "start_claimed");

    let failed = finish_for_verdict(&validated, false, true);
    assert_eq!(failed, FinishState::FailedVerification);
    assert!(!failed.is_complete());
    let degraded = finish_for_verdict(&validated, true, false);
    assert_eq!(degraded, FinishState::DegradedNoProof);
    assert!(!degraded.is_complete());
    let complete = finish_for_verdict(&validated, true, true);
    assert_eq!(complete, FinishState::VerifiedComplete);
    assert!(complete.is_complete());
}
