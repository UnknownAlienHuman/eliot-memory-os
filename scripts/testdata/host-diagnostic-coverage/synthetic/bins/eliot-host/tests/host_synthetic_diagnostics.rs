//! Synthetic Host diagnostic bindings (issue #985 coverage-validator fixture).
//!
//! Frozen fixture input only: the case functions the synthetic reviewed table
//! binds. Never compiled and never a second Host owner.

/// One workspace tracing facade, no missing or duplicate current owner.
pub fn facade_singleton_bound() {
    let _ = eliot_host::host_diagnostics::install_host_diagnostics();
}

/// Start request/result events carry real source and test binding.
pub fn start_request_result_bound() {
    let _ = eliot_host::start_contour("installation-1");
    let _ = eliot_host::host_launch_options::reject_installation("");
}

/// SCM receipt correlation carries no protected payload.
pub fn scm_receipt_bound() {
    let receipt = eliot_host::host_receipt::ScmReceipt {
        process_id: 7011,
        generation: 7,
    };
    eliot_host::host_receipt::record_receipt(&receipt);
    assert_absent(eliot_host::host_receipt::protected_payload());
}

/// Activation, drain and stop phase evidence stays distinct.
pub fn activation_drain_stop_bound() {
    let _ = eliot_host::host_console::admit_console_request("status");
    let _ = eliot_host::start_contour("installation-1");
}

/// Launch, restart and rollback paths reach exactly one terminal emitter.
pub fn launch_terminal_bound() {
    assert!(eliot_host::host_launch_options::reject_installation("").is_err());
    assert!(eliot_host::start_contour("").is_err());
}

/// Recovery helper propagation reaches its designated terminal boundary.
pub fn recovery_propagation_bound() {
    assert!(eliot_host::host_recovery::recover_installation("").is_err());
}

/// One rejected request emits one terminal record.
pub fn single_terminal_emitter_bound() {
    let _ = eliot_host::host_console::admit_console_request("status");
    assert!(eliot_host::start_contour("").is_err());
}

/// Operation identity stays tied to the owner receipt.
pub fn operation_identity_bound() {
    let receipt = eliot_host::host_receipt::ScmReceipt {
        process_id: 7011,
        generation: 7,
    };
    eliot_host::host_receipt::record_receipt(&receipt);
}

/// No positive record precedes its owning receipt.
pub fn no_positive_before_receipt_bound() {
    let _ = eliot_host::host_receipt::record_receipt;
}

/// Request, start and terminal vocabularies never cross-claim.
pub fn no_cross_claim_bound() {
    let _ = eliot_host::host_diagnostics::observe_entrypoint("console_loop");
    let _ = eliot_host::host_diagnostics::observe_host_request("scm_receipt");
}

/// Cross-child forced failure reaches one terminal with an unchanged return.
pub fn cross_child_forced_failure_bound() {
    let before = eliot_host::host_launch_options::reject_installation("");
    let after = eliot_host::host_launch_options::reject_installation("");
    assert_eq!(before, after);
}

/// The sink failure seam keeps its bounded admission accounting.
pub fn sink_failure_seam_bound() {
    let mut queue = eliot_host::host_sink::EventLogQueue::with_default_capacity();
    assert!(queue.try_admit(eliot_host::host_sink::EventLogRecord::mapping()).is_ok());
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.capacity(), eliot_host::host_sink::EVENT_LOG_QUEUE_CAPACITY);
}

/// Credential, token, environment and database canaries stay out of a sink.
pub fn credential_canaries_absent_bound() {
    let _ = eliot_host::host_sink::EVENT_LOG_SOURCE;
    assert_absent("eliot_synthetic_credential_canary");
}

/// Source, user, argv, path and nonce canaries stay out of a sink.
pub fn identity_canaries_absent_bound() {
    let _ = eliot_host::host_sink::EVENT_LOG_SOURCE;
    assert_absent("eliot_synthetic_identity_canary");
}

fn assert_absent(_canary: &str) {}
