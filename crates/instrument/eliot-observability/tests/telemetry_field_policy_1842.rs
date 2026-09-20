//! Minimal proof for issue #1842: telemetry field policies govern the
//! running Kernel-daemon path before operational evidence is retained.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use eliot_contracts::ClockReading;
use eliot_observability::field_policy::{
    RetentionStore, TelemetryFieldFamily, daemon_emit_gate, kernel_emit_gate, policy_for,
    retention_for,
};
use eliot_observability::{MetricAggregation, MetricSample};

const SECRET: &str = "sk-live-1842-proof-secret";

fn proof_clock() -> ClockReading {
    ClockReading {
        valid_time_ms: Some(1),
        known_time_ms: Some(1),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

#[test]
fn inventory_covers_running_path_families() {
    let required = [
        TelemetryFieldFamily::QueryMetadata,
        TelemetryFieldFamily::Principal,
        TelemetryFieldFamily::Session,
        TelemetryFieldFamily::TaskId,
        TelemetryFieldFamily::TraceId,
        TelemetryFieldFamily::RouteFingerprint,
        TelemetryFieldFamily::Lease,
        TelemetryFieldFamily::IoHandle,
        TelemetryFieldFamily::OperationalLog,
        TelemetryFieldFamily::CrashReport,
        TelemetryFieldFamily::AuditReceipt,
    ];
    for family in required {
        let policy =
            policy_for(family).unwrap_or_else(|| panic!("missing policy for {}", family.as_str()));
        policy
            .validate()
            .unwrap_or_else(|_| panic!("invalid policy for {}", family.as_str()));
        assert!(
            !policy.recipients.is_empty(),
            "recipients for {}",
            family.as_str()
        );
        policy.retention.validate().expect("retention per family");
    }
    assert_eq!(
        TelemetryFieldFamily::all().len(),
        eliot_observability::field_policy::field_policy_inventory().len(),
        "inventory covers every governed family"
    );
}

#[test]
fn secret_absent_from_labels_with_handle_recorded() {
    let mut candidate = BTreeMap::new();
    candidate.insert("query_hash".to_owned(), "q:9f2".to_owned());
    candidate.insert("task_ref".to_owned(), "task-1842".to_owned());
    candidate.insert("authorization".to_owned(), format!("Bearer {SECRET}"));
    candidate.insert("prompt".to_owned(), "summarize this".to_owned());
    candidate.insert("note".to_owned(), "x".repeat(300));

    let kernel = kernel_emit_gate(TelemetryFieldFamily::QueryMetadata, &candidate);
    let daemon = daemon_emit_gate(TelemetryFieldFamily::QueryMetadata, &candidate);
    assert_eq!(kernel, daemon, "both roots enforce the same gate");

    for value in kernel.labels.values() {
        assert!(!value.contains(SECRET), "secret must not survive in labels");
        assert!(
            !value.contains("summarize this"),
            "content key must be redacted"
        );
    }
    assert!(
        !kernel.labels.contains_key("prompt"),
        "forbidden key must be renamed"
    );
    assert!(
        kernel.is_clean(),
        "scrubbed labels carry no secret or content"
    );
    assert_eq!(
        kernel.handles.len(),
        3,
        "secret, forbidden key and content recorded"
    );
    for handle in &kernel.handles {
        assert!(
            handle.handle.starts_with("evh:"),
            "immutable handle identity"
        );
        assert!(
            !handle.handle.contains(SECRET),
            "handle discloses no secret"
        );
        assert!(
            !handle.redaction_status.trim().is_empty(),
            "redaction status recorded"
        );
    }

    let sample = MetricSample {
        sample_id: "sample-1842".to_owned(),
        name: "emit_gate_proof".to_owned(),
        aggregation: MetricAggregation::Counter,
        value: 1.0,
        unit: "count".to_owned(),
        captured_at: proof_clock(),
        trace: None,
        labels: kernel.labels.clone(),
    };
    sample.validate().expect("scrubbed metric labels validate");
}

#[test]
fn retention_metadata_distinct_per_store() {
    let raw = retention_for(TelemetryFieldFamily::IoHandle).expect("raw output policy");
    let audit = retention_for(TelemetryFieldFamily::AuditReceipt).expect("audit policy");
    let metric = retention_for(TelemetryFieldFamily::MetricSample).expect("metric policy");

    assert_eq!(raw.store, RetentionStore::BlobStore);
    assert_eq!(audit.store, RetentionStore::AuditCanonical);
    assert_eq!(metric.store, RetentionStore::MetricBuffer);
    assert_ne!(raw.retention_bound, audit.retention_bound);
    assert_ne!(audit.retention_bound, metric.retention_bound);
    assert_ne!(raw.retention_bound, metric.retention_bound);
    for policy in [&raw, &audit, &metric] {
        policy.validate().expect("retention export erasure defined");
    }
}
