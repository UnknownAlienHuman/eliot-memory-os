#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::match_wildcard_for_single_variants
)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::{AttemptId, RouteFingerprint};

use crate::model_control::{BillingClass, ModelRole};

use super::{
    DiversityDimension, DiversityError, DiversityOutcome, DiversityRequirement, decide_diversity,
    decide_swarm_diversity, validate_no_secret_or_fixed_input, validate_one_primary_per_host,
};
use crate::model_control::{
    BillingEvidence, CapabilityObservation, CapabilityStatus, ModelAvailability,
    ModelCatalogueEntry, QuotaDisposition, QuotaObservation, RouteAdmissionStatus,
    RouteHealthStatus,
};

const NOW: u64 = 10_000;

fn route(provider: &str, model: &str, host: &str, suffix: &str) -> RouteFingerprint {
    RouteFingerprint {
        host_family: host.to_owned(),
        adapter: "eliot-agent-opencode".to_owned(),
        protocol_transport: "http+sse".to_owned(),
        runtime_hash: format!("runtime-{suffix}"),
        adapter_hash: "adapter-v1".to_owned(),
        provider: provider.to_owned(),
        model: model.to_owned(),
        auth_billing: "account-scope-1".to_owned(),
        serializer_hash: "serializer-v1".to_owned(),
        tool_semantics_hash: "tools-v1".to_owned(),
        reasoning_mode: "high".to_owned(),
        continuation_behavior: "native-resume".to_owned(),
        feature_flags_hash: "features-v1".to_owned(),
    }
}

fn entry(
    entry_id: &str,
    host: &str,
    provider: &str,
    model: &str,
    family: &str,
) -> ModelCatalogueEntry {
    ModelCatalogueEntry {
        entry_id: entry_id.to_owned(),
        account_scope: "account-scope-1".to_owned(),
        host_family: host.to_owned(),
        provider_id: provider.to_owned(),
        model_id: model.to_owned(),
        model_family: family.to_owned(),
        route: route(provider, model, host, entry_id),
        route_admission: RouteAdmissionStatus::Admitted,
        route_health: RouteHealthStatus::Healthy,
        availability: ModelAvailability::Available,
        billing: BillingEvidence {
            class: BillingClass::Free,
            source: "provider-catalogue".to_owned(),
            receipt_ref: format!("billing-{entry_id}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
        },
        quota: QuotaObservation {
            disposition: QuotaDisposition::Available,
            source: "provider-catalogue".to_owned(),
            receipt_ref: format!("quota-{entry_id}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            reset_at_unix_ms: Some(NOW + 1_000),
            remaining_microunits: Some(10),
        },
        context_window: 200_000,
        cost_class: 1,
        latency_class: 1,
        capabilities: BTreeMap::from([(
            "coding".to_owned(),
            CapabilityObservation {
                status: CapabilityStatus::Supported,
                evidence_class: "runtime_probe".to_owned(),
                receipt_ref: format!("capability-{entry_id}"),
            },
        )]),
        role_eligibility: BTreeSet::from([
            ModelRole::Worker,
            ModelRole::Challenger,
            ModelRole::Verifier,
            ModelRole::MainAgent,
        ]),
        evidence_refs: vec![format!("evidence-{entry_id}")],
    }
}

fn attempt(value: &str) -> AttemptId {
    AttemptId::new(value).expect("attempt")
}

#[test]
fn secret_input_is_fail_closed() {
    let mut bad = entry("good", "opencode", "provider-a", "model-a", "family-a");
    bad.entry_id = "api_key-leak".to_owned();
    assert!(matches!(
        validate_no_secret_or_fixed_input(&[bad]),
        Err(DiversityError::SecretInput(_))
    ));

    let mut bad_route = entry("good2", "opencode", "provider-a", "model-a", "family-a");
    bad_route.route.model = "secret-model".to_owned();
    // route secret still triggers via entry checks
    // We inject secret via evidence_refs containing secret fragment
    let mut secret_evidence = entry("good3", "opencode", "provider-a", "model-a", "family-a");
    secret_evidence.evidence_refs = vec!["bearer-token-ref".to_owned()];
    assert!(matches!(
        validate_no_secret_or_fixed_input(&[secret_evidence]),
        Err(DiversityError::SecretInput(_))
    ));

    let ok = entry("ok", "opencode", "provider-a", "model-a", "family-a");
    assert!(validate_no_secret_or_fixed_input(&[ok]).is_ok());
}

#[test]
fn fixed_model_drift_is_fail_closed() {
    let fixed = entry(
        "fixed",
        "opencode",
        "provider-a",
        "universal-model",
        "family-a",
    );
    assert!(matches!(
        validate_no_secret_or_fixed_input(&[fixed]),
        Err(DiversityError::FixedModelDrift(_))
    ));

    let fixed2 = entry(
        "fixed2",
        "opencode",
        "provider-a",
        "fixed-model",
        "family-a",
    );
    assert!(matches!(
        validate_no_secret_or_fixed_input(&[fixed2]),
        Err(DiversityError::FixedModelDrift(_))
    ));

    let ok = entry("ok", "opencode", "provider-a", "ordinary-model", "family-a");
    assert!(validate_no_secret_or_fixed_input(&[ok]).is_ok());
}

#[test]
fn one_primary_per_host_is_enforced() {
    let mut selections = BTreeMap::new();
    selections.insert(
        attempt("attempt-1"),
        (
            ModelRole::MainAgent,
            entry("e1", "codex", "provider-a", "model-a", "family-a"),
        ),
    );
    selections.insert(
        attempt("attempt-2"),
        (
            ModelRole::MainAgent,
            entry("e2", "codex", "provider-b", "model-b", "family-b"),
        ),
    );
    assert!(matches!(
        validate_one_primary_per_host(&selections),
        Err(DiversityError::OnePrimaryPerHost(host)) if host == "codex"
    ));

    let mut ok = BTreeMap::new();
    ok.insert(
        attempt("attempt-1"),
        (
            ModelRole::MainAgent,
            entry("e1", "codex", "provider-a", "model-a", "family-a"),
        ),
    );
    ok.insert(
        attempt("attempt-2"),
        (
            ModelRole::MainAgent,
            entry("e2", "claude", "provider-b", "model-b", "family-b"),
        ),
    );
    assert!(validate_one_primary_per_host(&ok).is_ok());

    // Workers may share host without violation.
    let mut workers_share = BTreeMap::new();
    workers_share.insert(
        attempt("attempt-1"),
        (
            ModelRole::Worker,
            entry("e1", "codex", "provider-a", "model-a", "family-a"),
        ),
    );
    workers_share.insert(
        attempt("attempt-2"),
        (
            ModelRole::Worker,
            entry("e2", "codex", "provider-b", "model-b", "family-b"),
        ),
    );
    assert!(validate_one_primary_per_host(&workers_share).is_ok());
}

#[test]
fn challenger_verifier_host_route_family_diversity_is_explicit() {
    let primary = entry("primary", "codex", "provider-a", "model-a", "family-a");
    let challenger_same = entry(
        "challenger-same",
        "codex",
        "provider-a",
        "model-a",
        "family-a",
    );
    // Make route identical by using same provider/model/host/suffix that yields same route fingerprint
    // Use same host/provider/model but different entry_id still yields different runtime_hash suffix,
    // so to force route equality we clone primary's route.
    let mut challenger_same_route = challenger_same.clone();
    challenger_same_route.route = primary.route.clone();
    challenger_same_route.host_family = primary.host_family.clone();
    challenger_same_route.model_family = primary.model_family.clone();

    let primary_id = attempt("attempt-primary");
    let challenger_id = attempt("attempt-challenger");

    let req = DiversityRequirement::new(
        challenger_id.clone(),
        primary_id.clone(),
        BTreeSet::from([
            DiversityDimension::Host,
            DiversityDimension::Route,
            DiversityDimension::ModelFamily,
        ]),
    )
    .expect("requirement");

    let decision = decide_diversity(
        challenger_id.clone(),
        &challenger_same_route,
        Some((&primary_id, &primary)),
        Some(req.clone()),
    )
    .expect("decision");
    match decision.outcome {
        DiversityOutcome::Degraded(degraded) => {
            assert_eq!(degraded.attempt_id, challenger_id);
            assert!(degraded.gaps.contains(&DiversityDimension::Host));
            assert!(degraded.gaps.contains(&DiversityDimension::Route));
            assert!(degraded.gaps.contains(&DiversityDimension::ModelFamily));
            assert_eq!(degraded.requirement, req);
        }
        DiversityOutcome::Satisfied { .. } => panic!("expected degraded diversity"),
    }

    // Diverse challenger should satisfy.
    let challenger_diverse = entry(
        "challenger-diverse",
        "claude",
        "provider-b",
        "model-b",
        "family-b",
    );
    let req2 = DiversityRequirement::new(
        challenger_id.clone(),
        primary_id.clone(),
        BTreeSet::from([
            DiversityDimension::Host,
            DiversityDimension::Route,
            DiversityDimension::ModelFamily,
        ]),
    )
    .expect("requirement");
    let decision2 = decide_diversity(
        challenger_id.clone(),
        &challenger_diverse,
        Some((&primary_id, &primary)),
        Some(req2),
    )
    .expect("decision");
    assert!(matches!(
        decision2.outcome,
        DiversityOutcome::Satisfied { .. }
    ));
}

#[test]
fn decision_is_bound_to_exact_attempt_id() {
    let primary = entry("primary", "codex", "provider-a", "model-a", "family-a");
    let challenger = entry("challenger", "claude", "provider-b", "model-b", "family-b");
    let primary_id = attempt("attempt-primary");
    let challenger_id = attempt("attempt-challenger");
    let wrong_id = attempt("attempt-wrong");

    let req = DiversityRequirement::new(
        challenger_id.clone(),
        primary_id.clone(),
        BTreeSet::from([DiversityDimension::Host]),
    )
    .expect("requirement");

    // AttemptId mismatch should fail closed.
    let result = decide_diversity(
        wrong_id.clone(),
        &challenger,
        Some((&primary_id, &primary)),
        Some(req),
    );
    assert!(matches!(result, Err(DiversityError::InvalidField(_))));
}

#[test]
fn batch_decide_reports_degraded_and_preserves_candidate_only() {
    let primary = entry("primary", "codex", "provider-a", "model-a", "family-a");
    let mut challenger_same = entry("challenger", "codex", "provider-a", "model-a", "family-a");
    challenger_same.route = primary.route.clone();
    let verifier_diverse = entry(
        "verifier",
        "antigravity",
        "provider-c",
        "model-c",
        "family-c",
    );

    let primary_id = attempt("attempt-primary");
    let challenger_id = attempt("attempt-challenger");
    let verifier_id = attempt("attempt-verifier");

    let mut selections = BTreeMap::new();
    selections.insert(primary_id.clone(), (ModelRole::MainAgent, primary.clone()));
    selections.insert(
        challenger_id.clone(),
        (ModelRole::Challenger, challenger_same.clone()),
    );
    selections.insert(
        verifier_id.clone(),
        (ModelRole::Verifier, verifier_diverse.clone()),
    );

    let mut requirements = BTreeMap::new();
    requirements.insert(
        challenger_id.clone(),
        DiversityRequirement::new(
            challenger_id.clone(),
            primary_id.clone(),
            BTreeSet::from([
                DiversityDimension::Host,
                DiversityDimension::Route,
                DiversityDimension::ModelFamily,
            ]),
        )
        .expect("req"),
    );
    requirements.insert(
        verifier_id.clone(),
        DiversityRequirement::new(
            verifier_id.clone(),
            primary_id.clone(),
            BTreeSet::from([
                DiversityDimension::Host,
                DiversityDimension::Route,
                DiversityDimension::ModelFamily,
            ]),
        )
        .expect("req"),
    );

    let decisions = decide_swarm_diversity(&selections, &requirements).expect("decisions");
    let challenger_decision = decisions.get(&challenger_id).expect("challenger decision");
    assert!(matches!(
        challenger_decision.outcome,
        DiversityOutcome::Degraded(_)
    ));
    assert!(challenger_decision.candidate_only);
    assert!(!challenger_decision.dispatch_authority);
    assert!(challenger_decision.execution_zero);

    let verifier_decision = decisions.get(&verifier_id).expect("verifier decision");
    assert!(matches!(
        verifier_decision.outcome,
        DiversityOutcome::Satisfied { .. }
    ));
}

#[test]
fn degraded_diversity_is_explicit_not_silent_reuse() {
    let primary = entry("primary", "opencode", "provider-a", "model-a", "family-x");
    let challenger = entry(
        "challenger",
        "opencode",
        "provider-a",
        "model-a",
        "family-x",
    );
    let primary_id = attempt("attempt-primary");
    let challenger_id = attempt("attempt-challenger");
    let req = DiversityRequirement::new(
        challenger_id.clone(),
        primary_id.clone(),
        BTreeSet::from([DiversityDimension::ModelFamily]),
    )
    .expect("req");
    let decision = decide_diversity(
        challenger_id.clone(),
        &challenger,
        Some((&primary_id, &primary)),
        Some(req),
    )
    .expect("decision");
    // Must be degraded, not silently satisfied.
    match decision.outcome {
        DiversityOutcome::Degraded(d) => {
            assert_eq!(d.gaps, vec![DiversityDimension::ModelFamily]);
        }
        DiversityOutcome::Satisfied { .. } => panic!("expected explicit degraded outcome"),
    }
}
