//! Daemon-side enforcement of the #1842 telemetry field policies.
//!
//! The shared policy crate (`eliot-observability`) defines the
//! recognisable-secret rule and the scrub/is-clean emission boundary; this
//! proof runs that rule through the real daemon emission path
//! (`eliotd::diagnostics`, the single funnel feeding tracing span fields and
//! rolling-log records). An input carrying a recognisable secret is absent
//! from emitted record lines and captures while `[redacted]` records the
//! redaction status; benign identities pass through unchanged.

use std::collections::BTreeMap;

use eliot_observability::field_policy::{
    RedactionReason, TelemetryFieldFamily, looks_like_secret, scrub_labels_for_emit,
    validate_labels_for_family,
};
use eliotd::diagnostics::{
    OwningComponent, RejectionReason, RejectionRecord, RequestReceipt, captured_records,
    carries_denied_content, install_capture, sanitize_detail, sanitize_identity,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Secrets shaped like the policy library's recognisable-secret rule that the
/// daemon's former substring markers alone did not deny.
const DENIED_SECRETS: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "xoxb-123456789012-abcdef",
];

fn assert_absent(haystack: &str, needle: &str) -> TestResult {
    if haystack.contains(needle) {
        return Err(format!("emitted telemetry leaks denied input {needle:?}").into());
    }
    Ok(())
}

#[test]
fn recognisable_secrets_are_redacted_before_daemon_emission() -> TestResult {
    let _guard = install_capture();
    for secret in DENIED_SECRETS {
        if !looks_like_secret(secret) {
            return Err(format!("policy library must recognise {secret:?} as a secret").into());
        }
        if !carries_denied_content(secret) {
            return Err(format!("daemon boundary must deny {secret:?}").into());
        }
        if sanitize_identity(secret) != eliotd::diagnostics::REDACTED {
            return Err(format!("daemon identity boundary must redact {secret:?}").into());
        }
        if sanitize_detail(secret) != eliotd::diagnostics::REDACTED {
            return Err(format!("daemon detail boundary must redact {secret:?}").into());
        }
        let record = RequestReceipt::of(secret, "op-1").emit();
        if !record.line().contains(eliotd::diagnostics::REDACTED) {
            return Err(
                format!("emitted record must carry the redaction status for {secret:?}").into(),
            );
        }
        assert_absent(record.line(), secret)?;
    }
    for line in captured_records() {
        for secret in DENIED_SECRETS {
            assert_absent(&line, secret)?;
        }
    }
    Ok(())
}

#[test]
fn pem_detail_is_redacted_from_rolling_log_records() -> TestResult {
    let _guard = install_capture();
    let pem = "-----BEGIN RSA PRIVATE KEY-----";
    if !looks_like_secret(pem) {
        return Err("policy library must recognise a PEM header as secret-bearing".into());
    }
    let record = RejectionRecord::of(
        RejectionReason::GenericFailure,
        OwningComponent::DaemonRuntime,
        pem,
    )
    .emit();
    if !record.line().contains(eliotd::diagnostics::REDACTED) {
        return Err("rejection record must carry the redaction status".into());
    }
    assert_absent(record.line(), pem)?;
    for line in captured_records() {
        assert_absent(&line, pem)?;
    }
    Ok(())
}

#[test]
fn benign_identities_pass_through_unchanged() -> TestResult {
    let _guard = install_capture();
    for identity in ["task-1", "req-abc", "scope:governor", "epoch:3/gen:7"] {
        if looks_like_secret(identity) || carries_denied_content(identity) {
            return Err(format!("benign identity {identity:?} must not be denied").into());
        }
        if sanitize_identity(identity) != identity {
            return Err(format!("benign identity {identity:?} must pass through").into());
        }
        let record = RequestReceipt::of(identity, "op-1").emit();
        if !record.line().contains(identity) {
            return Err(format!("emitted record must retain {identity:?}").into());
        }
    }
    Ok(())
}

#[test]
fn unscrubbed_secret_labels_fail_the_policy_gate() -> TestResult {
    let mut raw = BTreeMap::new();
    raw.insert("task".to_owned(), "AKIAIOSFODNN7EXAMPLE".to_owned());
    if validate_labels_for_family(TelemetryFieldFamily::OperationalLog, &raw).is_ok() {
        return Err("unscrubbed secret label must be rejected".into());
    }
    let scrubbed = scrub_labels_for_emit(TelemetryFieldFamily::OperationalLog, &raw);
    if !scrubbed.is_clean(TelemetryFieldFamily::OperationalLog) {
        return Err("scrubbed output must pass the emission gate".into());
    }
    if scrubbed.handles.len() != 1
        || !RedactionReason::all_statuses().contains(&scrubbed.handles[0].redaction_status.as_str())
    {
        return Err(
            "scrub must record exactly one handle with a permitted redaction status".into(),
        );
    }
    for value in scrubbed.labels.values() {
        assert_absent(value, "AKIAIOSFODNN7EXAMPLE")?;
    }
    Ok(())
}
