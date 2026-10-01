//! Minimal acceptance proof for issue #1935 (I7.16/I7.22/I7.23).
//!
//! Only the two behaviors named under acceptance are proved:
//! 1. visible lifecycle/tool events without reliable pre-action enforcement
//!    are recorded as observed (not enforced) and the derived
//!    `GovernanceProfile` does not authorize enforcement-dependent operations;
//! 2. a later blind interval or route mismatch emits a new `GovernanceProfile`
//!    revision and a previously dependent capability is rejected under it.

use eliot_integration_coverage::{
    ALL_EVENTS, AdapterAdmissionIdentity, CoverageError, DispatchOrdering, EventCompleteness,
    EventCoverage, EventDisposition, EvidenceAvailability, GovernorAuthorityObservation,
    GovernorCoverageDerivation, IntegrationCoverageProfile, LogicalEvent,
    ObservationCursorBounds, ObservationEventPage, ObservationOwner, ObservationRosterPage,
    ObservationSelectors, ObservationStreamReadback, OriginalBridgeEventObservation,
    SourceReadback, TraceFreshness, WatchdogEvidence,
};

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("expected Ok, got {error:?}"),
    }
}

fn observed_event(event: LogicalEvent) -> EventCoverage {
    EventCoverage {
        event,
        disposition: EventDisposition::Observed,
        ordering: DispatchOrdering::PostDispatch,
        completeness: EventCompleteness::Complete,
        proof_ceiling: "observed-effect".to_owned(),
        source: "host-event-envelope".to_owned(),
        gaps: Vec::new(),
    }
}

fn enforced_pre_action(event: LogicalEvent) -> EventCoverage {
    EventCoverage {
        event,
        disposition: EventDisposition::Enforced,
        ordering: DispatchOrdering::PreDispatch,
        completeness: EventCompleteness::Complete,
        proof_ceiling: "enforced-action".to_owned(),
        source: "host-event-envelope".to_owned(),
        gaps: Vec::new(),
    }
}

fn fresh_watchdog() -> WatchdogEvidence {
    WatchdogEvidence {
        supervisor_id: "watchdog:supervisor-1".to_owned(),
        fresh: true,
        summary: "trace supervision current".to_owned(),
    }
}

fn issue_1935_native_observation(
    event_kind: &str,
    descriptor_digest: &str,
) -> GovernorAuthorityObservation {
    let adapter = AdapterAdmissionIdentity {
        descriptor_sha256: descriptor_digest.to_owned(),
        profile_id: "opencode-profile".to_owned(),
        profile_sha256: "p".repeat(64),
        executable_sha256: "x".repeat(64),
    };
    let payload = serde_json::json!({
        "event_kind": event_kind,
        "opencode_process_binding": {
            "process_id": 42,
            "process_start_time_100ns": 1234,
            "image_path": "C:/OpenCode/opencode.exe",
            "adapter_artifact_sha256": "a".repeat(64),
            "adapter_descriptor_sha256": descriptor_digest,
            "installation_profile_sha256": adapter.profile_sha256,
            "native_event_classes": [
                "session.created", "session.compacted", "session.error", "session.idle",
                "permission.asked", "permission.replied", "file.edited", "todo.updated"
            ],
            "native_hook_classes": ["tool.execute.before", "tool.execute.after"],
            "executable_sha256": adapter.executable_sha256,
            "launch_nonce": "broker-launch-nonce",
            "introduction_digest": "i".repeat(64),
        }
    });
    let envelope = serde_json::json!({
        "stream_id": "opencode.host.events",
        "producer_id": "opencode-bridge",
        "event_id": "event-1",
        "sequence": 1,
        "payload_type": "opencode.host.event",
        "payload_or_blob_ref": {"inline": {"Json": payload}}
    });
    let owner = ObservationOwner {
        owner_namespace: "owner-namespace".to_owned(),
        owner_list_sequence: 1,
        authority_lineage: "authority-lineage".to_owned(),
        principal: "principal".to_owned(),
        producer_id: "opencode-bridge".to_owned(),
        local_stream: "opencode.host.events".to_owned(),
        creating_connection: "connection".to_owned(),
        creating_launch_nonce: "broker-launch-nonce".to_owned(),
        creating_session_epoch: 1,
        revision: 1,
        incarnation: 1,
    };
    let record = OriginalBridgeEventObservation {
        event_id: "event-1".to_owned(),
        sequence: 1,
        producer_generation: 1,
        authority_epoch: String::new(),
        envelope_sha256: "e".repeat(64),
        transport_hash: "t".repeat(64),
        stored_envelope_bytes: envelope.to_string(),
        normalized_projection_bytes: envelope.to_string(),
        staging_connection: "connection".to_owned(),
        staged_at_ms: 1,
        phase: "committed".to_owned(),
        redacted: false,
        redaction_reason: String::new(),
        redacted_classes: Vec::new(),
        redaction_marker: String::new(),
        redaction_version: 0,
        admitted_source: "source".to_owned(),
        admitted_scope: "scope".to_owned(),
        admitted_policy_revision: 1,
        adapter_version: "adapter".to_owned(),
        transformation_version: 1,
        requested_route: "route".to_owned(),
        actual_route: "route".to_owned(),
        normalization_warnings: Vec::new(),
    };
    let page = ObservationEventPage {
        owner: owner.clone(),
        after_event_sequence: 0,
        observed_through_sequence: 1,
        cursor: ObservationCursorBounds {
            durable_sequence: 1,
            observed_sequence: 1,
            acked_sequence: 1,
            compacted_sequence: 0,
        },
        records: vec![record],
        gaps: Vec::new(),
        gap_total: 0,
        continuation: None,
    };
    GovernorAuthorityObservation {
        adapter: Some(adapter),
        source: SourceReadback::Available {
            selectors: ObservationSelectors {
                after_owner_sequence: 0,
                after_event_sequence: 0,
                page_limit: 10,
            },
            roster: ObservationRosterPage {
                authority_lineage: owner.authority_lineage.clone(),
                principal: owner.principal.clone(),
                owner_cutoff: 1,
                owner_total: 1,
                owners: vec![owner.clone()],
                continuation: None,
            },
            streams: vec![ObservationStreamReadback { owner, page }],
            next: None,
        },
        watchdog: EvidenceAvailability::Available {
            evidence: fresh_watchdog(),
        },
        trace: EvidenceAvailability::Available {
            evidence: TraceFreshness::Fresh,
        },
    }
}

#[test]
fn observed_lifecycle_without_enforcement_denies_enforcement_ops() {
    let candidate = must(IntegrationCoverageProfile::candidate(
        "host:adapter:fingerprint-a",
        ALL_EVENTS.iter().copied().map(observed_event).collect(),
        EventCompleteness::Complete,
        "observed-effect",
        "discovery-scan",
        Vec::new(),
    ));
    // Discovery output alone cannot derive production claims.
    let mut governor = GovernorCoverageDerivation::new();
    assert_eq!(
        governor.derive(&candidate, &fresh_watchdog(), TraceFreshness::Fresh),
        Err(CoverageError::CandidateNotVerified)
    );
    // Exact active-fingerprint production observation verifies the profile.
    let coverage = must(candidate.verify("host:adapter:fingerprint-a", true));
    assert_eq!(
        coverage.disposition(LogicalEvent::PreToolUse),
        Some(EventDisposition::Observed)
    );
    assert_eq!(
        coverage.disposition(LogicalEvent::PermissionRequest),
        Some(EventDisposition::Observed)
    );
    let profile = must(governor.derive(&coverage, &fresh_watchdog(), TraceFreshness::Fresh));
    assert!(!profile.authorizes_enforcement);
    // Enforcement-dependent operations are not authorized; observation-only
    // operations still are.
    let blocking = must(governor.issue_capability("cap:enforcing-tool", true, false));
    assert_eq!(
        governor.authorize(&blocking.capability_id),
        Err(CoverageError::CapabilityNotAuthorized(
            "cap:enforcing-tool".to_owned()
        ))
    );
    let observing = must(governor.issue_capability("cap:observe-only", false, false));
    must(governor.authorize(&observing.capability_id));
}

#[test]
fn invalid_coverage_is_rejected_fail_closed() {
    // An omitted logical event is rejected, never treated as unavailable.
    let mut missing = ALL_EVENTS
        .iter()
        .copied()
        .map(observed_event)
        .collect::<Vec<_>>();
    missing.pop();
    assert!(
        IntegrationCoverageProfile::candidate(
            "host:adapter:fingerprint-a",
            missing,
            EventCompleteness::Partial,
            "observed-effect",
            "host-event-envelope",
            vec!["missing Stop/FinishAttempt axis".to_owned()],
        )
        .is_err()
    );

    // A COMPLETE profile with a partial event is contradictory.
    let mut partial_event = ALL_EVENTS
        .iter()
        .copied()
        .map(observed_event)
        .collect::<Vec<_>>();
    for event in &mut partial_event {
        if event.event == LogicalEvent::PostToolUse {
            event.completeness = EventCompleteness::Partial;
            event.gaps.push("blind interval 12:00-12:07".to_owned());
        }
    }
    assert!(
        IntegrationCoverageProfile::candidate(
            "host:adapter:fingerprint-a",
            partial_event,
            EventCompleteness::Complete,
            "observed-effect",
            "host-event-envelope",
            Vec::new(),
        )
        .is_err()
    );

    // A PARTIAL event without named gap evidence is rejected.
    let mut gapless = ALL_EVENTS
        .iter()
        .copied()
        .map(observed_event)
        .collect::<Vec<_>>();
    for event in &mut gapless {
        if event.event == LogicalEvent::PostToolUse {
            event.completeness = EventCompleteness::Partial;
        }
    }
    assert!(
        IntegrationCoverageProfile::candidate(
            "host:adapter:fingerprint-a",
            gapless,
            EventCompleteness::Partial,
            "observed-effect",
            "host-event-envelope",
            vec!["blind interval 12:00-12:07".to_owned()],
        )
        .is_err()
    );

    // A COMPLETE event carrying gap evidence is rejected.
    let mut gapped = ALL_EVENTS
        .iter()
        .copied()
        .map(observed_event)
        .collect::<Vec<_>>();
    for event in &mut gapped {
        if event.event == LogicalEvent::PostToolUse {
            event.gaps.push("stale gap note".to_owned());
        }
    }
    assert!(
        IntegrationCoverageProfile::candidate(
            "host:adapter:fingerprint-a",
            gapped,
            EventCompleteness::Complete,
            "observed-effect",
            "host-event-envelope",
            Vec::new(),
        )
        .is_err()
    );

    // A candidate mutated after construction cannot be promoted.
    let mut profile = must(IntegrationCoverageProfile::candidate(
        "host:adapter:fingerprint-a",
        ALL_EVENTS.iter().copied().map(observed_event).collect(),
        EventCompleteness::Complete,
        "observed-effect",
        "discovery-scan",
        Vec::new(),
    ));
    profile.events.pop();
    assert!(profile.verify("host:adapter:fingerprint-a", true).is_err());
}

#[test]
fn coverage_loss_emits_new_revision_and_rejects_prior_capability() {
    let mut events: Vec<EventCoverage> = ALL_EVENTS.iter().copied().map(observed_event).collect();
    for event in &mut events {
        if matches!(
            event.event,
            LogicalEvent::PreToolUse | LogicalEvent::PermissionRequest
        ) {
            *event = enforced_pre_action(event.event);
        }
    }
    let coverage = must(
        must(IntegrationCoverageProfile::candidate(
            "host:adapter:fingerprint-a",
            events,
            EventCompleteness::Complete,
            "enforced-action",
            "host-event-envelope",
            Vec::new(),
        ))
        .verify("host:adapter:fingerprint-a", true),
    );
    let mut governor = GovernorCoverageDerivation::new();
    let before = must(governor.derive(&coverage, &fresh_watchdog(), TraceFreshness::Fresh));
    assert!(before.authorizes_enforcement);
    let capability = must(governor.issue_capability("cap:guarded-tool", true, true));
    must(governor.authorize(&capability.capability_id));

    // A blind interval on the tool-outcome stream degrades completeness.
    let mut degraded: Vec<EventCoverage> = ALL_EVENTS.iter().copied().map(observed_event).collect();
    for event in &mut degraded {
        if matches!(
            event.event,
            LogicalEvent::PreToolUse | LogicalEvent::PermissionRequest
        ) {
            *event = enforced_pre_action(event.event);
        }
        if event.event == LogicalEvent::PostToolUse {
            event.completeness = EventCompleteness::Partial;
            event.gaps.push("blind interval 12:00-12:07".to_owned());
        }
    }
    let degraded = must(
        must(IntegrationCoverageProfile::candidate(
            "host:adapter:fingerprint-a",
            degraded,
            EventCompleteness::Partial,
            "observed-effect",
            "host-event-envelope",
            vec!["blind interval 12:00-12:07".to_owned()],
        ))
        .verify("host:adapter:fingerprint-a", true),
    );
    let after = must(governor.derive(&degraded, &fresh_watchdog(), TraceFreshness::Fresh));
    assert!(after.revision > before.revision);
    assert!(matches!(
        governor.authorize(&capability.capability_id),
        Err(CoverageError::CapabilityRevoked(_)
            | CoverageError::StaleCapabilityBinding(_)
            | CoverageError::CapabilityNotAuthorized(_))
    ));

    // A route mismatch emits a further revision that authorizes nothing and
    // rejects capabilities bound to the lost fingerprint.
    let observer = must(governor.issue_capability("cap:observe-degraded", false, false));
    must(governor.authorize(&observer.capability_id));
    let (mismatch, revoked) = must(
        governor.report_route_mismatch("host:adapter:fingerprint-a", "host:adapter:fingerprint-b"),
    );
    assert!(mismatch.revision > after.revision);
    assert!(revoked.contains(&"cap:observe-degraded".to_owned()));
    assert!(governor.authorize(&capability.capability_id).is_err());
    assert!(governor.authorize(&observer.capability_id).is_err());
}

#[test]
fn issue_1935_broker_joined_original_hook_is_observed_without_enforcement() {
    let descriptor = "d".repeat(64);
    let profile = must(IntegrationCoverageProfile::from_authority_observation(
        &issue_1935_native_observation("tool.execute.before", &descriptor),
        descriptor,
    ));

    let pre_tool = profile
        .events
        .iter()
        .find(|event| event.event == LogicalEvent::PreToolUse)
        .expect("all logical event axes are present");
    assert_eq!(pre_tool.disposition, EventDisposition::Observed);
    assert_eq!(pre_tool.ordering, DispatchOrdering::PreDispatch);
    assert_eq!(pre_tool.completeness, EventCompleteness::Unknown);
    assert!(!profile.verified);
    assert!(profile
        .events
        .iter()
        .all(|event| event.disposition != EventDisposition::Enforced));
}

#[test]
fn issue_1935_unmatched_broker_process_binding_refuses_native_coverage() {
    let descriptor = "d".repeat(64);
    let mut observation = issue_1935_native_observation("tool.execute.before", &descriptor);
    if let SourceReadback::Available { streams, .. } = &mut observation.source {
        let envelope: serde_json::Value = serde_json::from_str(
            &streams[0].page.records[0].normalized_projection_bytes,
        )
        .expect("fixture envelope is JSON");
        let mut envelope = envelope;
        envelope["payload_or_blob_ref"]["inline"]["Json"]["opencode_process_binding"]
            ["adapter_descriptor_sha256"] = serde_json::Value::String("z".repeat(64));
        streams[0].page.records[0].normalized_projection_bytes = envelope.to_string();
    }
    let profile = must(IntegrationCoverageProfile::from_authority_observation(
        &observation,
        descriptor,
    ));

    assert_eq!(
        profile.disposition(LogicalEvent::PreToolUse),
        Some(EventDisposition::Unavailable)
    );
    assert!(!profile.verified);
    assert!(profile
        .events
        .iter()
        .all(|event| event.disposition != EventDisposition::Enforced));
    assert!(profile.gaps.iter().any(|gap| gap.contains("unverified")));
}
