#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_dreamer_contracts::bundle::{
    BundleCompleteness, BundleMaterial, DreamInputBundle, OmissionHandle, SourceDisposition,
};
use eliot_dreamer_contracts::draft::{ModelDraft, RawProviderOutput};
use eliot_dreamer_contracts::model_route::{
    CostUsageReceipt, MODEL_ROUTE_SCHEMA_VERSION, ModelRouteDisposition, ModelRouteOutcome,
    ModelRoutePrivacy, ModelRouteRequest, bundle_digest_of,
};

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(), ResourceGeneration::genesis())
}

fn fence_other() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(2).expect("sequence"),
    )
    .expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn bundle() -> DreamInputBundle {
    DreamInputBundle {
        schema_version: 1,
        job_id: "job-1".to_string(),
        scope_id: "scope-1".to_string(),
        task_id: "task-1".to_string(),
        state_fence: fence(),
        manifest_digest: sha256_hex(b"manifest"),
        materials: vec![BundleMaterial {
            handle: "source-a".to_string(),
            disposition: SourceDisposition::Required,
            bytes: 12,
            digest: sha256_hex(b"source-a"),
        }],
        omissions: vec![OmissionHandle {
            handle: "source-b".to_string(),
            reason: "upstream unavailable".to_string(),
            reversible: true,
            scope_id: "scope-1".to_string(),
            task_id: "task-1".to_string(),
            digest: sha256_hex(b"omission-b"),
            nonrecoverable_reason: None,
        }],
        completeness: BundleCompleteness::PartialForScope,
        authoritative_denominator: None,
    }
}

fn request() -> ModelRouteRequest {
    let digest = bundle_digest_of(&bundle()).expect("bundle digest");
    ModelRouteRequest {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: "job-1".to_string(),
        bundle_digest: digest,
        state_fence: fence(),
        allowed_routes: vec!["provider-a/v1".to_string()],
        timeout_ms: 5_000,
        cancelled: false,
        privacy: ModelRoutePrivacy::LocalOnly,
    }
}

fn raw(route: &str) -> RawProviderOutput {
    let raw_bytes = br#"{"hypothesis":"cache helps"}"#.to_vec();
    let output_digest = sha256_hex(&raw_bytes);
    RawProviderOutput {
        schema_version: 1,
        job_id: "job-1".to_string(),
        provider_route: route.to_string(),
        raw_bytes,
        output_digest,
    }
}

fn draft() -> ModelDraft {
    ModelDraft {
        schema_version: 1,
        job_id: "job-1".to_string(),
        statement: "Caching cuts tail latency.".to_string(),
        source_handles: vec!["source-a".to_string()],
        counterevidence: vec!["cold start unaffected".to_string()],
        uncertainty: "medium".to_string(),
        expected_benefit: "Lower p99 if hit rate holds.".to_string(),
        recommended_probes: vec!["measure hit rate".to_string()],
        invalidation_conditions: vec!["hit rate below 50%".to_string()],
        declared_confirmed_handles: Vec::new(),
    }
}

fn receipt() -> CostUsageReceipt {
    CostUsageReceipt {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: "job-1".to_string(),
        input_bytes: 512,
        output_bytes: 256,
        model_calls: 1,
        wall_ms: 120,
    }
}

fn completed_outcome() -> ModelRouteOutcome {
    let req = request();
    ModelRouteOutcome {
        schema_version: MODEL_ROUTE_SCHEMA_VERSION,
        job_id: req.job_id.clone(),
        bundle_digest: req.bundle_digest.clone(),
        provider_route: Some("provider-a/v1".to_string()),
        disposition: ModelRouteDisposition::Completed,
        raw: None,
        draft: Some(draft()),
        receipt: receipt(),
        state_fence: fence(),
        note: "draft produced within budget".to_string(),
    }
}

#[test]
fn valid_request_binds_bundle_and_completed_outcome_binds_request() {
    let req = request();
    req.validate().expect("request validates");
    req.validate_binds_bundle(&bundle())
        .expect("request binds bundle");
    assert_eq!(req.request_digest().expect("digest").len(), 64);
    let outcome = completed_outcome();
    outcome.validate().expect("outcome validates");
    outcome
        .validate_binding(&req)
        .expect("outcome binds request");
}

#[test]
fn timeout_disposition_requires_meeting_the_admitted_timeout() {
    let req = request();
    let mut timed_out = completed_outcome();
    timed_out.disposition = ModelRouteDisposition::Timeout;
    timed_out.provider_route = None;
    timed_out.draft = None;
    timed_out.receipt.wall_ms = req.timeout_ms;
    timed_out.note = "provider exceeded deadline".to_string();
    timed_out.validate().expect("timeout shape validates");
    timed_out
        .validate_binding(&req)
        .expect("timeout meeting budget binds");

    let mut early = timed_out.clone();
    early.receipt.wall_ms = req.timeout_ms - 1;
    assert!(
        early.validate_binding(&req).is_err(),
        "timeout below budget must not bind"
    );

    let mut completed_late = completed_outcome();
    completed_late.receipt.wall_ms = req.timeout_ms + 1;
    assert!(
        completed_late.validate_binding(&req).is_err(),
        "completed past the deadline must not bind"
    );
}

#[test]
fn pre_cancelled_request_only_binds_a_cancelled_outcome() {
    let bundle_digest = bundle_digest_of(&bundle()).expect("digest");
    let cancelled_req = ModelRouteRequest {
        cancelled: true,
        ..request()
    };
    cancelled_req
        .validate()
        .expect("cancelled request validates");
    let mut outcome = completed_outcome();
    outcome.bundle_digest = bundle_digest.clone();
    assert!(
        outcome.validate_binding(&cancelled_req).is_err(),
        "completed must not bind a pre-cancelled request"
    );
    let cancelled_outcome = ModelRouteOutcome {
        provider_route: None,
        disposition: ModelRouteDisposition::Cancelled,
        raw: None,
        draft: None,
        receipt: CostUsageReceipt {
            wall_ms: 5,
            model_calls: 0,
            ..receipt()
        },
        note: "cancelled before provider call".to_string(),
        ..outcome
    };
    cancelled_outcome.validate().expect("cancelled validates");
    cancelled_outcome
        .validate_binding(&cancelled_req)
        .expect("cancelled binds a pre-cancelled request");
}

#[test]
fn partial_carries_both_payloads_and_malformed_carries_only_raw() {
    let req = request();
    let mut partial = completed_outcome();
    partial.disposition = ModelRouteDisposition::Partial;
    partial.raw = Some(raw("provider-a/v1"));
    partial
        .validate()
        .expect("partial with raw and draft validates");
    partial.validate_binding(&req).expect("partial binds");

    let mut completed_with_raw = completed_outcome();
    completed_with_raw.raw = Some(raw("provider-a/v1"));
    assert!(
        completed_with_raw.validate().is_err(),
        "completed must not carry raw bytes"
    );

    let mut malformed = completed_outcome();
    malformed.disposition = ModelRouteDisposition::Malformed;
    malformed.draft = None;
    malformed.raw = Some(raw("provider-a/v1"));
    malformed.validate().expect("malformed with raw validates");
    malformed.validate_binding(&req).expect("malformed binds");

    let mut malformed_with_draft = malformed.clone();
    malformed_with_draft.draft = Some(draft());
    assert!(
        malformed_with_draft.validate().is_err(),
        "malformed must not carry a draft"
    );
}

#[test]
fn over_bytes_route_and_receipt_bounds_fail_closed() {
    let mut over_receipt = completed_outcome();
    over_receipt.receipt.output_bytes = 1_048_576 + 1;
    assert!(
        over_receipt.validate().is_err(),
        "output over ceiling must fail"
    );

    let mut over_route = request();
    over_route.allowed_routes = vec!["r".repeat(129)];
    assert!(over_route.validate().is_err(), "route over 128 must fail");

    let mut over_statement = completed_outcome();
    let mut bad_draft = draft();
    bad_draft.statement = "s".repeat(16_385);
    over_statement.draft = Some(bad_draft);
    assert!(
        over_statement.validate().is_err(),
        "statement over 16384 must fail"
    );

    let mut empty_routes = request();
    empty_routes.allowed_routes = Vec::new();
    assert!(
        empty_routes.validate().is_err(),
        "empty denominator must fail"
    );

    let mut duplicated = request();
    duplicated.allowed_routes = vec!["provider-a/v1".to_string(), "provider-a/v1".to_string()];
    assert!(duplicated.validate().is_err(), "duplicate routes must fail");
}

#[test]
fn fence_mismatch_and_unknown_route_fail_binding() {
    let req = request();
    let mut fenced = completed_outcome();
    fenced.state_fence = fence_other();
    assert!(
        fenced.validate_binding(&req).is_err(),
        "foreign fence must not bind"
    );

    let mut foreign_route = completed_outcome();
    foreign_route.provider_route = Some("provider-unknown/v9".to_string());
    if let Some(raw) = foreign_route.raw.as_mut() {
        raw.provider_route = "provider-unknown/v9".to_string();
        raw.output_digest = sha256_hex(&raw.raw_bytes);
    }
    // Completed carries no raw; only the route needs to drift.
    assert!(
        foreign_route.validate_binding(&req).is_err(),
        "route outside the denominator must not bind"
    );
}

#[test]
fn replacement_provider_binds_without_rebuilding_the_consumer() {
    let digest = bundle_digest_of(&bundle()).expect("digest");
    let req = ModelRouteRequest {
        allowed_routes: vec!["provider-a/v1".to_string(), "provider-b/v1".to_string()],
        bundle_digest: digest,
        ..request()
    };
    req.validate().expect("two-route denominator validates");
    for route in ["provider-a/v1", "provider-b/v1"] {
        let mut outcome = completed_outcome();
        outcome.bundle_digest = req.bundle_digest.clone();
        outcome.provider_route = Some(route.to_string());
        // Completed carries no raw; the draft job binding is route-independent.
        outcome.validate().expect("replacement draft validates");
        outcome
            .validate_binding(&req)
            .expect("either admitted route binds");
    }
}
