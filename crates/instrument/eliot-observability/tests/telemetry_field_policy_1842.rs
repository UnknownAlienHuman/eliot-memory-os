//! Proof for issue #1842: telemetry field policies govern the running
//! Kernel-daemon path before operational evidence is retained.
//!
//! [`scrub_labels_for_emit`](eliot_observability::field_policy::scrub_labels_for_emit)
//! is the single emission boundary; there are no per-root facades. Family
//! [`LabelDisposition`](eliot_observability::field_policy::LabelDisposition)
//! is enforced both when scrubbing and when validating labels, and
//! [`ScrubbedLabels`](eliot_observability::field_policy::ScrubbedLabels)`::is_clean`
//! verifies every audit property for the emitting family in both directions:
//! every recorded handle is emitted, and every emitted `evh` handle is recorded.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use eliot_contracts::ClockReading;
use eliot_observability::field_policy::{
    LabelDisposition, RedactedHandle, ScrubbedLabels, TelemetryFieldFamily, disposition_for,
    field_policy_inventory, is_handle_value_for_family, scrub_labels_for_emit,
    validate_labels_for_family,
};
use eliot_observability::{
    BufferDisposition, BufferLimits, MetricAggregation, MetricSample, ObservabilityBuffer,
    ObservabilityError,
};

const SECRET: &str = "sk-live-1842-proof-secret";

fn proof_clock() -> ClockReading {
    ClockReading {
        valid_time_ms: Some(1),
        known_time_ms: Some(1),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

fn proof_sample(labels: BTreeMap<String, String>) -> MetricSample {
    MetricSample {
        sample_id: "sample-1842".to_owned(),
        name: "emit_gate_proof".to_owned(),
        aggregation: MetricAggregation::Counter,
        value: 1.0,
        unit: "count".to_owned(),
        captured_at: proof_clock(),
        trace: None,
        labels,
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
        let policy = eliot_observability::field_policy::policy_for(family)
            .unwrap_or_else(|| panic!("missing policy for {}", family.as_str()));
        policy
            .validate()
            .unwrap_or_else(|_| panic!("invalid policy for {}", family.as_str()));
        assert!(
            !policy.recipients.is_empty(),
            "recipients for {}",
            family.as_str()
        );
        policy.retention.validate().expect("retention per family");
        assert_eq!(
            disposition_for(family),
            policy.label_disposition,
            "disposition mapping matches the published policy for {}",
            family.as_str()
        );
    }
    assert_eq!(
        TelemetryFieldFamily::all().len(),
        field_policy_inventory().len(),
        "inventory covers every governed family"
    );
}

#[test]
fn handle_only_values_never_appear_as_raw_labels() {
    let mut candidate = BTreeMap::new();
    candidate.insert("query_hash".to_owned(), "q:9f2".to_owned());
    candidate.insert("task_ref".to_owned(), "task-1842".to_owned());
    candidate.insert("note".to_owned(), "benign".to_owned());

    let scrubbed = scrub_labels_for_emit(TelemetryFieldFamily::QueryMetadata, &candidate);
    assert_eq!(
        scrubbed.labels.len(),
        candidate.len(),
        "handle-only keeps one label per input"
    );
    assert_eq!(
        scrubbed.handles.len(),
        candidate.len(),
        "every handle-only value is recorded"
    );
    for (key, value) in &scrubbed.labels {
        let raw = candidate.get(key).expect("handle-only keeps the key");
        assert_ne!(value, raw, "raw value must not survive for {key}");
        assert!(
            is_handle_value_for_family(value, TelemetryFieldFamily::QueryMetadata),
            "handle-only emits family-bound handles"
        );
    }
    for handle in &scrubbed.handles {
        assert_eq!(handle.redaction_status, "redacted:handle-only");
    }
    assert!(
        scrubbed.is_clean(TelemetryFieldFamily::QueryMetadata),
        "handle-only scrub output is clean for its family"
    );
    validate_labels_for_family(TelemetryFieldFamily::QueryMetadata, &scrubbed.labels)
        .expect("scrubbed handle-only labels validate");

    let sample = proof_sample(scrubbed.labels.clone());
    assert!(
        !matches!(sample.validate(), Err(ObservabilityError::SensitiveLabel)),
        "metric validation shares the family boundary"
    );
}

#[test]
fn forbidden_family_never_emits() {
    let mut candidate = BTreeMap::new();
    candidate.insert("receipt".to_owned(), "r-1".to_owned());
    candidate.insert("decision".to_owned(), "admit".to_owned());

    let scrubbed = scrub_labels_for_emit(TelemetryFieldFamily::AuditReceipt, &candidate);
    assert!(scrubbed.labels.is_empty(), "forbidden emits no labels");
    assert!(scrubbed.handles.is_empty(), "forbidden emits no handles");
    assert!(
        scrubbed.is_clean(TelemetryFieldFamily::AuditReceipt),
        "empty forbidden output is clean"
    );
    validate_labels_for_family(TelemetryFieldFamily::AuditReceipt, &scrubbed.labels)
        .expect("empty forbidden labels validate");
    assert!(
        matches!(
            validate_labels_for_family(TelemetryFieldFamily::AuditReceipt, &candidate),
            Err(ObservabilityError::SensitiveLabel)
        ),
        "any forbidden label is rejected on the validation path"
    );
}

#[test]
fn allowed_family_scrubs_secrets_content_and_forbidden_keys() {
    let mut candidate = BTreeMap::new();
    candidate.insert("query_hash".to_owned(), "q:9f2".to_owned());
    candidate.insert("task_ref".to_owned(), "task-1842".to_owned());
    candidate.insert("authorization".to_owned(), format!("Bearer {SECRET}"));
    candidate.insert("prompt".to_owned(), "summarize this".to_owned());
    candidate.insert("note".to_owned(), "x".repeat(300));

    let scrubbed = scrub_labels_for_emit(TelemetryFieldFamily::MetricSample, &candidate);
    for value in scrubbed.labels.values() {
        assert!(!value.contains(SECRET), "secret must not survive in labels");
        assert!(
            !value.contains("summarize this"),
            "content key must be redacted"
        );
    }
    assert!(
        !scrubbed.labels.contains_key("prompt"),
        "forbidden key must be renamed"
    );
    assert_eq!(
        scrubbed
            .labels
            .get("query_hash")
            .expect("benign identifier"),
        "q:9f2",
        "allowed opaque identifiers still pass through"
    );
    assert!(
        scrubbed.is_clean(TelemetryFieldFamily::MetricSample),
        "scrubbed labels carry no secret or content"
    );
    assert_eq!(
        scrubbed.handles.len(),
        3,
        "secret, forbidden key and content recorded"
    );
    for handle in &scrubbed.handles {
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

    let sample = proof_sample(scrubbed.labels.clone());
    sample.validate().expect("scrubbed metric labels validate");

    let limits = BufferLimits {
        max_events: 8,
        max_metrics: 8,
        max_gaps: 8,
    };
    let mut buffer = ObservabilityBuffer::new(limits).expect("buffer");
    assert_eq!(
        buffer.append_metric(sample.clone()).expect("append"),
        BufferDisposition::Accepted,
        "scrubbed metric reaches the bounded buffer"
    );
    assert_eq!(
        buffer.append_metric(sample).expect("replay"),
        BufferDisposition::Replayed,
        "identical replay is idempotent"
    );
    buffer.snapshot().validate().expect("snapshot validates");
}

#[test]
fn is_clean_rejects_forbidden_keys() {
    let mut labels = BTreeMap::new();
    labels.insert("prompt".to_owned(), "q:9f2".to_owned());
    let scrubbed = ScrubbedLabels {
        labels,
        handles: Vec::new(),
    };
    assert!(
        !scrubbed.is_clean(TelemetryFieldFamily::MetricSample),
        "forbidden key must fail is_clean"
    );
    assert!(
        !scrubbed.is_clean(TelemetryFieldFamily::QueryMetadata),
        "forbidden key must fail is_clean for handle-only too"
    );

    let mut screened = BTreeMap::new();
    screened.insert("redacted_evidence_0".to_owned(), format!("Bearer {SECRET}"));
    let screened_scrubbed = ScrubbedLabels {
        labels: screened,
        handles: Vec::new(),
    };
    assert!(
        !screened_scrubbed.is_clean(TelemetryFieldFamily::MetricSample),
        "secret values fail even under a safe renamed key"
    );
}

#[test]
fn is_clean_rejects_surviving_content_for_restricted_families() {
    let mut raw = BTreeMap::new();
    raw.insert("query_hash".to_owned(), "q:9f2".to_owned());
    let raw_scrubbed = ScrubbedLabels {
        labels: raw,
        handles: Vec::new(),
    };
    assert!(
        !raw_scrubbed.is_clean(TelemetryFieldFamily::QueryMetadata),
        "raw value must not pass for a handle-only family"
    );

    let mut leaked = BTreeMap::new();
    leaked.insert("receipt".to_owned(), "r-1".to_owned());
    let leaked_scrubbed = ScrubbedLabels {
        labels: leaked,
        handles: Vec::new(),
    };
    assert!(
        !leaked_scrubbed.is_clean(TelemetryFieldFamily::AuditReceipt),
        "any forbidden label must fail"
    );

    let mut secret = BTreeMap::new();
    secret.insert("authorization".to_owned(), format!("Bearer {SECRET}"));
    let secret_scrubbed = ScrubbedLabels {
        labels: secret,
        handles: Vec::new(),
    };
    assert!(
        !secret_scrubbed.is_clean(TelemetryFieldFamily::MetricSample),
        "secret must not survive even for allowed families"
    );

    let mut content = BTreeMap::new();
    content.insert("note".to_owned(), "x".repeat(300));
    let content_scrubbed = ScrubbedLabels {
        labels: content,
        handles: Vec::new(),
    };
    assert!(
        !content_scrubbed.is_clean(TelemetryFieldFamily::MetricSample),
        "over-long content must not survive"
    );
}

#[test]
fn is_clean_requires_family_bound_structurally_valid_handles() {
    let mut candidate = BTreeMap::new();
    candidate.insert("query_hash".to_owned(), "q:9f2".to_owned());
    let good = scrub_labels_for_emit(TelemetryFieldFamily::QueryMetadata, &candidate);
    assert!(good.is_clean(TelemetryFieldFamily::QueryMetadata));
    assert!(
        !good.is_clean(TelemetryFieldFamily::Principal),
        "handles bound to one family must not pass for another"
    );

    let mut wrong_family = good.clone();
    wrong_family.handles[0].family = TelemetryFieldFamily::Principal;
    assert!(
        !wrong_family.is_clean(TelemetryFieldFamily::QueryMetadata),
        "handle record must name the emitting family"
    );

    let mut bad_shape = good.clone();
    bad_shape.handles[0].handle = "evh:query_metadata:not-hex".to_owned();
    bad_shape
        .labels
        .insert("query_hash".to_owned(), bad_shape.handles[0].handle.clone());
    assert!(
        !bad_shape.is_clean(TelemetryFieldFamily::QueryMetadata),
        "malformed handle identity must fail"
    );

    let mut bad_status = good.clone();
    bad_status.handles[0].redaction_status = "redacted:something-else".to_owned();
    assert!(
        !bad_status.is_clean(TelemetryFieldFamily::QueryMetadata),
        "unknown redaction status must fail"
    );

    let mut blank_source = good.clone();
    blank_source.handles[0].source_key = "   ".to_owned();
    assert!(
        !blank_source.is_clean(TelemetryFieldFamily::QueryMetadata),
        "blank source key must fail"
    );

    let mut unemitted = good.clone();
    unemitted.handles.push(RedactedHandle {
        handle: format!("evh:query_metadata:{}", "1".repeat(64)),
        family: TelemetryFieldFamily::QueryMetadata,
        source_key: "extra".to_owned(),
        redaction_status: "redacted:handle-only".to_owned(),
    });
    assert!(
        !unemitted.is_clean(TelemetryFieldFamily::QueryMetadata),
        "handles must be bound to an emitted value"
    );

    let mut count_mismatch = good.clone();
    count_mismatch.labels.insert(
        "unrecorded".to_owned(),
        format!("evh:query_metadata:{}", "2".repeat(64)),
    );
    assert!(
        !count_mismatch.is_clean(TelemetryFieldFamily::QueryMetadata),
        "every handle-only label needs a recorded handle"
    );
}

#[test]
fn is_clean_requires_safe_emitted_keys() {
    let oversized: BTreeMap<String, String> = (0..17)
        .map(|index| (format!("k{index}"), "v".to_owned()))
        .collect();
    let oversized_scrubbed = ScrubbedLabels {
        labels: oversized,
        handles: Vec::new(),
    };
    assert!(
        !oversized_scrubbed.is_clean(TelemetryFieldFamily::MetricSample),
        "cardinality above the bounded limit must fail"
    );

    for key in ["secret_ref", "auth_token", "stdout", "raw_payload"] {
        let mut labels = BTreeMap::new();
        labels.insert(key.to_owned(), "v".to_owned());
        let scrubbed = ScrubbedLabels {
            labels,
            handles: Vec::new(),
        };
        assert!(
            !scrubbed.is_clean(TelemetryFieldFamily::MetricSample),
            "forbidden key {key} must fail"
        );
    }

    let mut blank = BTreeMap::new();
    blank.insert("   ".to_owned(), "v".to_owned());
    assert!(
        !ScrubbedLabels {
            labels: blank,
            handles: Vec::new()
        }
        .is_clean(TelemetryFieldFamily::MetricSample),
        "blank keys are unsafe"
    );
}

#[test]
fn is_clean_accounts_every_emitted_handle_for_allowed_families() {
    // Residual gap (PR #2260 re-audit): an Allowed-family label set carrying
    // an emitted `evh` handle with no matching RedactedHandle record passed
    // `is_clean`, because only the record-to-emission direction was checked.
    let orphan = format!("evh:metric_sample:{}", "3".repeat(64));
    let mut labels = BTreeMap::new();
    labels.insert("task_ref".to_owned(), "task-1842".to_owned());
    labels.insert("evidence".to_owned(), orphan.clone());
    let orphaned = ScrubbedLabels {
        labels,
        handles: Vec::new(),
    };
    assert!(
        !orphaned.is_clean(TelemetryFieldFamily::MetricSample),
        "emitted handle without a recorded handle must fail is_clean"
    );

    // A malformed `evh:`-shaped value is still a handle claim: without a
    // (necessarily valid) matching record it must fail fail-closed.
    let mut spoofed = BTreeMap::new();
    spoofed.insert("task_ref".to_owned(), "task-1842".to_owned());
    spoofed.insert("evidence".to_owned(), "evh:not-a-handle".to_owned());
    assert!(
        !ScrubbedLabels {
            labels: spoofed,
            handles: Vec::new(),
        }
        .is_clean(TelemetryFieldFamily::MetricSample),
        "spoof-shaped evh value without a record must fail is_clean"
    );

    // A foreign-family handle emitted under an Allowed family is unaccounted.
    let mut foreign = BTreeMap::new();
    foreign.insert("task_ref".to_owned(), "task-1842".to_owned());
    foreign.insert(
        "evidence".to_owned(),
        format!("evh:query_metadata:{}", "5".repeat(64)),
    );
    assert!(
        !ScrubbedLabels {
            labels: foreign,
            handles: Vec::new(),
        }
        .is_clean(TelemetryFieldFamily::MetricSample),
        "foreign-family handle without a record must fail is_clean"
    );

    // Positive control with removal: genuine scrub output is clean, but
    // dropping its handle record orphans the emitted handle.
    let mut candidate = BTreeMap::new();
    candidate.insert("task_ref".to_owned(), "task-1842".to_owned());
    candidate.insert("authorization".to_owned(), format!("Bearer {SECRET}"));
    let scrubbed = scrub_labels_for_emit(TelemetryFieldFamily::MetricSample, &candidate);
    assert!(
        scrubbed.is_clean(TelemetryFieldFamily::MetricSample),
        "recorded scrub output stays clean"
    );
    let mut dropped = scrubbed.clone();
    dropped.handles.clear();
    assert!(
        !dropped.is_clean(TelemetryFieldFamily::MetricSample),
        "dropping the handle record orphans the emitted handle"
    );
}

#[test]
fn is_clean_accounts_every_emitted_handle_for_handle_only_families() {
    // Duplicate records for one handle must not mask a second emitted handle
    // with no record of its own, even though the label/handle counts match.
    let first = format!("evh:query_metadata:{}", "6".repeat(64));
    let second = format!("evh:query_metadata:{}", "7".repeat(64));
    let record = |handle: String, source: &str| RedactedHandle {
        handle,
        family: TelemetryFieldFamily::QueryMetadata,
        source_key: source.to_owned(),
        redaction_status: "redacted:handle-only".to_owned(),
    };
    let mut labels = BTreeMap::new();
    labels.insert("a".to_owned(), first.clone());
    labels.insert("b".to_owned(), second.clone());
    let masked = ScrubbedLabels {
        labels,
        handles: vec![record(first.clone(), "a"), record(first, "b")],
    };
    assert!(
        !masked.is_clean(TelemetryFieldFamily::QueryMetadata),
        "masked unrecorded handle must fail is_clean despite matching counts"
    );
}

#[test]
fn family_validation_enforces_disposition_on_raw_input() {
    let mut raw = BTreeMap::new();
    raw.insert("query_hash".to_owned(), "q:9f2".to_owned());
    assert!(
        matches!(
            validate_labels_for_family(TelemetryFieldFamily::QueryMetadata, &raw),
            Err(ObservabilityError::SensitiveLabel)
        ),
        "raw handle-only values are rejected"
    );

    let mut secret = BTreeMap::new();
    secret.insert("authorization".to_owned(), format!("Bearer {SECRET}"));
    assert!(
        validate_labels_for_family(TelemetryFieldFamily::MetricSample, &secret).is_err(),
        "raw secrets are rejected for allowed families"
    );

    let mut forbidden_key = BTreeMap::new();
    forbidden_key.insert("prompt".to_owned(), "q:9f2".to_owned());
    assert!(
        validate_labels_for_family(TelemetryFieldFamily::MetricSample, &forbidden_key).is_err(),
        "forbidden keys are rejected for allowed families"
    );

    let scrubbed = scrub_labels_for_emit(TelemetryFieldFamily::TaskId, &raw);
    validate_labels_for_family(TelemetryFieldFamily::TaskId, &scrubbed.labels)
        .expect("allowed scrub output validates");
    assert!(
        scrubbed.is_clean(TelemetryFieldFamily::TaskId),
        "allowed scrub output is clean"
    );
    assert_eq!(
        disposition_for(TelemetryFieldFamily::TaskId),
        LabelDisposition::Allowed
    );
}

#[test]
fn retention_metadata_distinct_per_store() {
    use eliot_observability::field_policy::{RetentionStore, retention_for};

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
