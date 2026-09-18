//! Focused staffing-slot binding tests for issue #481.
//!
//! Proof ceiling: `SWARM_STAFFING_CANDIDATE_PACKAGE_PROOF_ONLY`.

use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::{LowercaseSha256, RouteFingerprint};
use eliot_agent_coordinator::{
    BillingClass, BillingEvidence, DiversityDimension, HumanModelPreferencePolicy,
    MODEL_CATALOGUE_SCHEMA_VERSION, MODEL_PREFERENCE_SCHEMA_VERSION, ModelAvailability,
    ModelCatalogueEntry, ModelCatalogueSnapshot, ModelControlError, ModelRole,
    ModelSelectionReceipt, QuotaDisposition, QuotaObservation, RoleModelPreference,
    RouteAdmissionStatus, RouteHealthStatus, StaffingGap, StaffingIndependenceOutcome,
    SwarmStaffingCandidate, SwarmStaffingError, SwarmStaffingRequest, compile_model_selection,
    compile_swarm_staffing,
};
use eliot_contracts::sha256_hex;

const NOW: u64 = 10_000;
const ACCOUNT: &str = "account-scope-1";
const CATALOGUE_ID: &str = "catalogue-staffing";
const POLICY_ID: &str = "human-policy";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn digest(seed: &str) -> TestResult<LowercaseSha256> {
    Ok(serde_json::from_value(serde_json::json!(sha256_hex(
        format!("staffing-slot-fixture-{seed}").as_bytes()
    )))?)
}

fn route(host: &str, provider: &str, model: &str, suffix: &str) -> TestResult<RouteFingerprint> {
    Ok(RouteFingerprint {
        host_family: host.to_owned(),
        adapter: "eliot-agent-opencode".to_owned(),
        protocol_transport: "http+sse".to_owned(),
        runtime_hash: digest(&format!("runtime-{suffix}"))?,
        adapter_hash: digest(&format!("adapter-{suffix}"))?,
        provider: provider.to_owned(),
        model: model.to_owned(),
        auth_billing: ACCOUNT.to_owned(),
        serializer_hash: digest(&format!("serializer-{suffix}"))?,
        tool_semantics_hash: digest(&format!("tools-{suffix}"))?,
        reasoning_mode: "default".to_owned(),
        continuation_behavior: "native-resume".to_owned(),
        feature_flags_hash: digest(&format!("features-{suffix}"))?,
    })
}

fn entry(
    entry_id: &str,
    host: &str,
    provider: &str,
    model: &str,
    family: &str,
    role: ModelRole,
) -> TestResult<ModelCatalogueEntry> {
    Ok(ModelCatalogueEntry {
        entry_id: entry_id.to_owned(),
        account_scope: ACCOUNT.to_owned(),
        host_family: host.to_owned(),
        provider_id: provider.to_owned(),
        model_id: model.to_owned(),
        model_family: family.to_owned(),
        route: route(host, provider, model, entry_id)?,
        route_admission: RouteAdmissionStatus::Admitted,
        route_health: RouteHealthStatus::Healthy,
        availability: ModelAvailability::Available,
        billing: BillingEvidence {
            class: BillingClass::Free,
            source: "test-billing".to_owned(),
            receipt_ref: format!("billing-{entry_id}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
        },
        quota: QuotaObservation {
            disposition: QuotaDisposition::Available,
            source: "test-quota".to_owned(),
            receipt_ref: format!("quota-{entry_id}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            reset_at_unix_ms: Some(NOW + 1_000),
            remaining_microunits: Some(1),
        },
        context_window: 128_000,
        cost_class: 0,
        latency_class: 0,
        capabilities: BTreeMap::new(),
        role_eligibility: BTreeSet::from([role]),
        evidence_refs: vec![format!("evidence-{entry_id}")],
    })
}

/// Four single-role entries on four disjoint host/provider/model-family
/// routes, so a complete staffing stays independent on every dimension.
fn snapshot() -> TestResult<ModelCatalogueSnapshot> {
    let specs = [
        (
            "entry-main",
            "host-a",
            "provider-a",
            "model-a",
            "family-a",
            ModelRole::MainAgent,
        ),
        (
            "entry-worker",
            "host-b",
            "provider-b",
            "model-b",
            "family-b",
            ModelRole::Worker,
        ),
        (
            "entry-challenger",
            "host-c",
            "provider-c",
            "model-c",
            "family-c",
            ModelRole::Challenger,
        ),
        (
            "entry-verifier",
            "host-d",
            "provider-d",
            "model-d",
            "family-d",
            ModelRole::Verifier,
        ),
    ];
    let mut entries = Vec::with_capacity(specs.len());
    for (entry_id, host, provider, model, family, role) in specs {
        entries.push(entry(entry_id, host, provider, model, family, role)?);
    }
    Ok(ModelCatalogueSnapshot {
        schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
        snapshot_id: CATALOGUE_ID.to_owned(),
        account_scope: ACCOUNT.to_owned(),
        collector_identity: "test-collector".to_owned(),
        observed_at_unix_ms: NOW - 100,
        expires_at_unix_ms: NOW + 100,
        entries,
    })
}

fn role_preference(role: ModelRole) -> RoleModelPreference {
    RoleModelPreference {
        role,
        preferred: Vec::new(),
        denied: Vec::new(),
        allowed_billing: BTreeSet::from([BillingClass::Free]),
        allow_paid_fallback: false,
        allow_degraded_routes: false,
        minimum_context_window: 1,
        maximum_cost_class: 10,
        maximum_latency_class: 10,
        required_capabilities: BTreeSet::new(),
    }
}

fn policy(roles: &[ModelRole]) -> HumanModelPreferencePolicy {
    HumanModelPreferencePolicy {
        schema_version: MODEL_PREFERENCE_SCHEMA_VERSION.to_owned(),
        policy_id: POLICY_ID.to_owned(),
        revision: "revision-1".to_owned(),
        account_scope: ACCOUNT.to_owned(),
        roles: roles.iter().map(|role| role_preference(*role)).collect(),
    }
}

fn receipt(
    snapshot: &ModelCatalogueSnapshot,
    policy: &HumanModelPreferencePolicy,
    role: ModelRole,
    selection_id: &str,
) -> TestResult<ModelSelectionReceipt> {
    Ok(compile_model_selection(
        snapshot,
        policy,
        role,
        selection_id,
        NOW,
    )?)
}

fn request(
    staffing_id: &str,
    demand: Vec<ModelRole>,
    selections: Vec<ModelSelectionReceipt>,
    snapshot: ModelCatalogueSnapshot,
    policy: HumanModelPreferencePolicy,
    now: u64,
) -> SwarmStaffingRequest {
    SwarmStaffingRequest {
        staffing_id: staffing_id.to_owned(),
        demand,
        selections,
        catalogue: snapshot,
        policy,
        now_unix_ms: now,
    }
}

fn full_roles() -> Vec<ModelRole> {
    vec![
        ModelRole::MainAgent,
        ModelRole::Worker,
        ModelRole::Challenger,
        ModelRole::Verifier,
    ]
}

fn full_receipts(
    snapshot: &ModelCatalogueSnapshot,
    policy: &HumanModelPreferencePolicy,
) -> TestResult<Vec<ModelSelectionReceipt>> {
    full_roles()
        .iter()
        .map(|role| {
            receipt(
                snapshot,
                policy,
                *role,
                &format!("selection-{}", format!("{role:?}").to_lowercase()),
            )
        })
        .collect()
}

fn assert_slot_binding(
    candidate: &SwarmStaffingCandidate,
    sources: &BTreeMap<ModelRole, &ModelSelectionReceipt>,
) {
    assert_eq!(candidate.slots.len(), sources.len());
    for slot in &candidate.slots {
        let source = sources[&slot.role];
        assert_eq!(slot.selection_id, source.selection_id);
        assert_eq!(slot.selection_digest, source.selection_digest);
        assert_eq!(slot.account_scope, ACCOUNT);
        assert_eq!(slot.catalogue_snapshot_id, CATALOGUE_ID);
        assert_eq!(slot.catalogue_digest, source.catalogue_digest);
        assert_eq!(slot.preference_policy_id, POLICY_ID);
        assert_eq!(slot.preference_revision, "revision-1");
        assert_eq!(
            slot.preference_policy_digest,
            source.preference_policy_digest
        );
        assert_eq!(slot.selected, source.selected);
        assert_eq!(slot.selected.route, source.selected.route);
        assert!(!slot.slot_digest.is_empty());
    }
}

fn assert_wire_ceiling(candidate: &SwarmStaffingCandidate) -> TestResult {
    assert!(candidate.candidate_only);
    assert!(!candidate.dispatch_authority);
    assert_eq!(
        candidate.execution,
        eliot_agent_coordinator::ZeroModelExecutionCounters::zero()
    );
    let round_trip: SwarmStaffingCandidate =
        serde_json::from_value(serde_json::to_value(candidate)?)?;
    assert_eq!(round_trip, *candidate);
    round_trip.validate()?;

    let mut tampered = serde_json::to_value(candidate)?;
    tampered["slots"][0]["selection_id"] = serde_json::json!("tampered-selection");
    assert!(
        serde_json::from_value::<SwarmStaffingCandidate>(tampered).is_err(),
        "changed slot bytes must conflict on the staffing digest"
    );
    let mut ceiling_tampered = serde_json::to_value(candidate)?;
    ceiling_tampered["candidate_only"] = serde_json::json!(false);
    assert!(
        serde_json::from_value::<SwarmStaffingCandidate>(ceiling_tampered).is_err(),
        "a non-candidate ceiling must fail closed on deserialize"
    );
    Ok(())
}

#[test]
fn staffed_slots_bind_exact_selection_identity_deterministically() -> TestResult {
    let snapshot = snapshot()?;
    let human_policy = policy(&full_roles());
    let receipts = full_receipts(&snapshot, &human_policy)?;
    let sources: BTreeMap<ModelRole, &ModelSelectionReceipt> =
        receipts.iter().map(|item| (item.role, item)).collect();

    let forward = request(
        "staffing-1",
        full_roles(),
        receipts.clone(),
        snapshot.clone(),
        human_policy.clone(),
        NOW,
    );
    let mut reversed_roles = full_roles();
    reversed_roles.reverse();
    let mut reversed_receipts = receipts.clone();
    reversed_receipts.reverse();
    let permuted = request(
        "staffing-1",
        reversed_roles,
        reversed_receipts,
        snapshot.clone(),
        human_policy.clone(),
        NOW,
    );

    let first = compile_swarm_staffing(&forward)?;
    let second = compile_swarm_staffing(&permuted)?;
    assert_eq!(
        first, second,
        "exact input permutation must produce identical staffing output"
    );

    assert_eq!(first.staffing_id, "staffing-1");
    assert!(first.is_complete());
    assert!(first.gaps.is_empty());
    assert_eq!(first.demand, full_roles());
    assert_slot_binding(&first, &sources);

    assert_eq!(first.independence.len(), 2);
    for decision in &first.independence {
        assert_eq!(decision.primary_role, ModelRole::MainAgent);
        assert!(
            decision.role == ModelRole::Challenger || decision.role == ModelRole::Verifier,
            "only Challenger/Verifier are classified, got {:?}",
            decision.role
        );
        assert!(
            matches!(decision.outcome, StaffingIndependenceOutcome::Satisfied),
            "disjoint routes must satisfy independence"
        );
    }
    assert_wire_ceiling(&first)
}

fn duplicate_selection_ids_fail(
    snapshot: &ModelCatalogueSnapshot,
    policy: &HumanModelPreferencePolicy,
) -> TestResult {
    let worker = receipt(snapshot, policy, ModelRole::Worker, "dup-id")?;
    let verifier = receipt(snapshot, policy, ModelRole::Verifier, "dup-id")?;
    let duplicated = request(
        "staffing-dup",
        vec![ModelRole::Worker, ModelRole::Verifier],
        vec![worker, verifier],
        snapshot.clone(),
        policy.clone(),
        NOW,
    );
    assert!(matches!(
        compile_swarm_staffing(&duplicated),
        Err(SwarmStaffingError::DuplicateIdentity(
            "staffing.selection_id"
        ))
    ));
    Ok(())
}

fn mixed_generations_fail(
    snapshot: &ModelCatalogueSnapshot,
    policy: &HumanModelPreferencePolicy,
) -> TestResult {
    let mut other = snapshot.clone();
    "catalogue-other".clone_into(&mut other.snapshot_id);
    let worker_current = receipt(snapshot, policy, ModelRole::Worker, "selection-worker")?;
    let verifier_other = receipt(&other, policy, ModelRole::Verifier, "selection-verifier")?;
    let mixed = request(
        "staffing-mixed",
        vec![ModelRole::Worker, ModelRole::Verifier],
        vec![worker_current, verifier_other],
        snapshot.clone(),
        policy.clone(),
        NOW,
    );
    assert!(matches!(
        compile_swarm_staffing(&mixed),
        Err(SwarmStaffingError::InvalidField("staffing.generation"))
    ));
    Ok(())
}

fn stale_selections_fail(
    snapshot: &ModelCatalogueSnapshot,
    policy: &HumanModelPreferencePolicy,
) -> TestResult {
    let worker = receipt(snapshot, policy, ModelRole::Worker, "selection-worker")?;
    let stale = request(
        "staffing-stale",
        vec![ModelRole::Worker],
        vec![worker],
        snapshot.clone(),
        policy.clone(),
        NOW + 1_000_000,
    );
    assert!(matches!(
        compile_swarm_staffing(&stale),
        Err(SwarmStaffingError::ModelControl(
            ModelControlError::StaleCatalogue
        ))
    ));
    Ok(())
}

fn missing_roles_stay_typed_gaps(
    snapshot: &ModelCatalogueSnapshot,
    policy: &HumanModelPreferencePolicy,
) -> TestResult {
    let worker = receipt(snapshot, policy, ModelRole::Worker, "selection-worker")?;
    let gapped = request(
        "staffing-gapped",
        vec![
            ModelRole::Worker,
            ModelRole::Challenger,
            ModelRole::Verifier,
        ],
        vec![worker],
        snapshot.clone(),
        policy.clone(),
        NOW,
    );
    let partial = compile_swarm_staffing(&gapped)?;
    assert!(!partial.is_complete());
    assert_eq!(partial.slots.len(), 1);
    assert_eq!(
        partial.gaps,
        vec![
            StaffingGap::MissingRole {
                role: ModelRole::Challenger
            },
            StaffingGap::MissingRole {
                role: ModelRole::Verifier
            },
        ]
    );
    assert_wire_ceiling(&partial)
}

/// Independence cannot be inferred from a different display name alone:
/// distinct entry/model labels on a shared host and model family stay
/// explicitly degraded.
fn shared_host_stays_degraded(snapshot: &ModelCatalogueSnapshot) -> TestResult {
    let shared = ModelCatalogueSnapshot {
        entries: vec![
            entry(
                "entry-display-prime",
                "solo-host",
                "provider-p",
                "model-prime",
                "family-solo",
                ModelRole::MainAgent,
            )?,
            entry(
                "entry-display-rival",
                "solo-host",
                "provider-c",
                "model-rival",
                "family-solo",
                ModelRole::Challenger,
            )?,
        ],
        ..snapshot.clone()
    };
    let shared_policy = policy(&[ModelRole::MainAgent, ModelRole::Challenger]);
    let primary = receipt(
        &shared,
        &shared_policy,
        ModelRole::MainAgent,
        "selection-main",
    )?;
    let rival = receipt(
        &shared,
        &shared_policy,
        ModelRole::Challenger,
        "selection-challenger",
    )?;
    assert_ne!(
        primary.selected.model_id, rival.selected.model_id,
        "fixture must differ in display name"
    );
    let dependent = request(
        "staffing-dependent",
        vec![ModelRole::MainAgent, ModelRole::Challenger],
        vec![primary, rival],
        shared,
        shared_policy,
        NOW,
    );
    let degraded = compile_swarm_staffing(&dependent)?;
    assert!(!degraded.is_complete());
    assert_eq!(degraded.slots.len(), 2);
    assert_eq!(degraded.independence.len(), 1);
    let decision = &degraded.independence[0];
    assert_eq!(decision.role, ModelRole::Challenger);
    assert_eq!(decision.primary_role, ModelRole::MainAgent);
    assert!(matches!(
        decision.outcome,
        StaffingIndependenceOutcome::Degraded { .. }
    ));
    assert_eq!(
        degraded.gaps,
        vec![StaffingGap::DegradedIndependence {
            role: ModelRole::Challenger,
            dimensions: vec![DiversityDimension::Host, DiversityDimension::ModelFamily],
        }]
    );
    Ok(())
}

#[test]
fn staffing_fails_closed_with_typed_gaps_and_explicit_independence() -> TestResult {
    let snapshot = snapshot()?;
    let human_policy = policy(&full_roles());
    duplicate_selection_ids_fail(&snapshot, &human_policy)?;
    mixed_generations_fail(&snapshot, &human_policy)?;
    stale_selections_fail(&snapshot, &human_policy)?;
    missing_roles_stay_typed_gaps(&snapshot, &human_policy)?;
    shared_host_stays_degraded(&snapshot)
}
