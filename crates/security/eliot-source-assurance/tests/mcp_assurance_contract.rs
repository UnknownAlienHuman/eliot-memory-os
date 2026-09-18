#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_source_assurance::{
    AdmissibleUse, AdmissionExpectation, AdmissionOutcome, AssuranceFinding, AxisStatus,
    EffectCeiling, GoverningSourceIdentity, GoverningSourceSet, InstructionTaint,
    OwnerSourceEvidence, PrivacyClass, QuarantineStatus, ScopeBindingProof, SourceAssurance,
    SourceAssuranceError, SourceAssurancePolicy, SourceFrontierBinding, SourceProvenance,
    SourceSnapshotBinding, SourceTrustProfile, ThreatStatus, TrustAxis,
};

fn digest(value: impl AsRef<[u8]>) -> String {
    blake3::hash(value.as_ref()).to_hex().to_string()
}

fn assurance() -> SourceAssurance {
    let frontier = SourceFrontierBinding {
        frontier_id: "frontier-1".into(),
        workspace_identity: "workspace-1".into(),
        repository_revision: "revision-1".into(),
        dirty_state_digest: digest("dirty"),
        generation: 1,
    };
    let scope = ScopeBindingProof {
        expected_scope: "scope-1".into(),
        observed_scope: "scope-1".into(),
        expected_generation: 1,
        observed_generation: 1,
        evidence_digest: digest("scope"),
    };
    SourceAssurance {
        schema_version: "eliot-source-assurance-v1".into(),
        governing_sources: GoverningSourceSet::new(
            "governing-set",
            "revision-1",
            vec![GoverningSourceIdentity {
                source_id: "architecture".into(),
                kind: "governing".into(),
                canonical_ref: "docs/ARCHITECTURE_CONTRACT.md".into(),
                content_digest: digest("architecture"),
                origin_ref: "owner-receipt:architecture".into(),
                revision: "revision-1".into(),
            }],
        )
        .expect("source fixture must be valid"),
        provenance: SourceProvenance {
            producer: "authenticated-owner".into(),
            acquisition_ref: "capture-1".into(),
            lineage_digest: digest("lineage"),
            authentication_ref: "owner-auth:1".into(),
        },
        trust: SourceTrustProfile {
            integrity: AxisStatus::Verified,
            freshness: AxisStatus::Verified,
            competence: AxisStatus::Verified,
            incentives: AxisStatus::Verified,
            independence: AxisStatus::Verified,
            privacy: PrivacyClass::Internal,
            instruction_taint: InstructionTaint::Data,
            threat: ThreatStatus::NoneObserved,
        },
        quarantine: QuarantineStatus::Clear,
        snapshot: SourceSnapshotBinding {
            snapshot_id: "snapshot-1".into(),
            source_set_id: "governing-set".into(),
            source_set_revision: "revision-1".into(),
            content_digest: digest("snapshot"),
            frontier_digest: digest(
                serde_json::to_vec(&frontier).expect("frontier fixture must encode"),
            ),
            state_fence: "fence-1".into(),
        },
        frontier,
        scope,
        requested_use: AdmissibleUse::Evidence,
        effect_ceiling: EffectCeiling::ReadOnlyCandidate,
    }
}

fn policy(source: &SourceAssurance) -> SourceAssurancePolicy {
    SourceAssurancePolicy {
        policy_version: "source-policy-v1".into(),
        expected_source_state_fence: "fence-1".into(),
        expectation: AdmissionExpectation {
            source_set_id: "governing-set".into(),
            source_set_revision: "revision-1".into(),
            frontier: source.frontier.clone(),
            scope: source.scope.clone(),
        },
        allowed_use: AdmissibleUse::Evidence,
        privacy_class: PrivacyClass::Internal,
        effect_ceiling: EffectCeiling::ReadOnlyCandidate,
        required_verifier: Some("verifier/source-v1".into()),
    }
}

fn owner_evidence() -> OwnerSourceEvidence {
    let source = assurance();
    OwnerSourceEvidence {
        owner_principal_ref: "principal/local-user".into(),
        evidence_ref: "owner-evidence:1".into(),
        request_id: "request-1".into(),
        original_request_sha256: "0".repeat(64),
        idempotency_key: "idempotency-1".into(),
        cancellation_id: "cancel-1".into(),
        session_id: "session-1".into(),
        state_fence_digest: "0".repeat(64),
        canonical_request_sha256: "0".repeat(64),
        verifier_ref: Some("verifier/source-v1".into()),
        policy: policy(&source),
        assurance: source,
    }
}

#[test]
fn data_source_is_admitted_for_explicit_evidence_use() {
    let evidence = owner_evidence();
    let outcome = evidence
        .assurance
        .admit_with_policy(&evidence.policy)
        .expect("policy evaluation should be deterministic");
    assert!(matches!(outcome, AdmissionOutcome::Admitted { .. }));
    assert_eq!(
        evidence.assurance.trust.instruction_taint,
        InstructionTaint::Data
    );
}

#[test]
fn failed_profile_axis_is_independent_and_cannot_be_filled_by_other_evidence() {
    let mut evidence = owner_evidence();
    evidence.assurance.trust.incentives = AxisStatus::Failed;
    let outcome = evidence
        .assurance
        .admit_with_policy(&evidence.policy)
        .expect("policy evaluation should return a typed outcome");
    let AdmissionOutcome::Quarantined { findings } = outcome else {
        panic!("failed profile axis must prevent admission");
    };
    assert!(findings.iter().any(|finding| {
        matches!(
            finding,
            eliot_source_assurance::AssuranceFinding::AxisFailed {
                axis: TrustAxis::Incentives
            }
        )
    }));
}

// WORK_UNIT_CASE 692/3: data requested as a procedure candidate claims
// instruction-like authority, so the taint finding fires on its own while
// every other field stays verified.
#[test]
fn data_requested_as_procedure_is_instruction_tainted() {
    let mut evidence = owner_evidence();
    evidence.assurance.requested_use = AdmissibleUse::ProcedureCandidate;
    evidence.policy.allowed_use = AdmissibleUse::ProcedureCandidate;
    let outcome = evidence
        .assurance
        .admit_with_policy(&evidence.policy)
        .expect("policy evaluation should return a typed outcome");
    let AdmissionOutcome::NeedsRevalidation { findings } = outcome else {
        panic!("tainted procedure request must not be admitted");
    };
    assert_eq!(findings, vec![AssuranceFinding::InstructionTainted]);
}

// WORK_UNIT_CASE 692/5: per-field use/effect/verifier requirements each
// produce their own typed finding and outcome on a genuine mismatch.
#[test]
fn integrity_verifier_and_owner_mismatches_are_typed() {
    let mut evidence = owner_evidence();
    evidence.assurance.trust.integrity = AxisStatus::Failed;
    let outcome = evidence
        .assurance
        .admit_with_policy(&evidence.policy)
        .expect("policy evaluation should return a typed outcome");
    let AdmissionOutcome::Quarantined { findings } = outcome else {
        panic!("failed integrity proof must quarantine");
    };
    assert_eq!(findings, vec![AssuranceFinding::InvalidIntegrity]);

    let evidence = owner_evidence();
    assert!(matches!(
        evidence.admit("principal/local-user"),
        Ok(AdmissionOutcome::Admitted { .. })
    ));

    let mut unverified = owner_evidence();
    unverified.verifier_ref = None;
    let outcome = unverified
        .admit("principal/local-user")
        .expect("owner evaluation should return a typed outcome");
    let AdmissionOutcome::NeedsRevalidation { findings } = outcome else {
        panic!("unsatisfied verifier requirement must need revalidation");
    };
    assert_eq!(findings, vec![AssuranceFinding::VerifierMismatch]);

    let mut spoofed = owner_evidence();
    spoofed.owner_principal_ref = "principal/attacker".into();
    let outcome = spoofed
        .admit("principal/local-user")
        .expect("owner evaluation should return a typed outcome");
    let AdmissionOutcome::Conflicted { findings } = outcome else {
        panic!("owner principal mismatch must conflict");
    };
    assert_eq!(findings, vec![AssuranceFinding::OwnerAuthenticationFailed]);
}

// WORK_UNIT_CASE 692/13: stale evidence needs owner refresh, an unknown
// policy revision is an explicit defect, and a missing policy never
// defaults to a permissive evaluation.
#[test]
fn unknown_policy_and_stale_evidence_are_explicit() {
    let evidence = owner_evidence();
    let mut unknown = evidence.policy.clone();
    unknown.policy_version = "source-policy-v2".into();
    let error = evidence
        .assurance
        .admit_with_policy(&unknown)
        .expect_err("unknown policy revision must not evaluate");
    assert!(matches!(error, SourceAssuranceError::UnsupportedSchema(_)));

    let mut stale_policy = evidence.policy.clone();
    stale_policy.expectation.frontier.generation = 2;
    let outcome = evidence
        .assurance
        .admit_with_policy(&stale_policy)
        .expect("policy evaluation should return a typed outcome");
    let AdmissionOutcome::NeedsRevalidation { findings } = outcome else {
        panic!("stale evidence must need revalidation");
    };
    assert!(findings.contains(&AssuranceFinding::StaleFrontier));

    let error = SourceAssurance::admit_optional_with_policy(Some(&evidence.assurance), None)
        .expect_err("missing policy must not default safe");
    assert!(matches!(
        error,
        SourceAssuranceError::MissingField("policy")
    ));
}

// WORK_UNIT_CASE 692/10: a transformation receipt extends lineage
// deterministically; a changed descriptor invalidates the prior receipt.
#[test]
fn lineage_receipt_append_is_deterministic() {
    let previous = digest("lineage");
    let first = eliot_source_assurance::append_lineage_receipt(&previous, b"transform:normalize")
        .expect("lineage append should be pure and total on valid input");
    let second = eliot_source_assurance::append_lineage_receipt(&previous, b"transform:normalize")
        .expect("lineage append should be deterministic");
    assert_eq!(first, second);
    let changed = eliot_source_assurance::append_lineage_receipt(&previous, b"transform:redact")
        .expect("changed descriptor must produce a receipt");
    assert_ne!(first, changed);
    assert!(
        eliot_source_assurance::append_lineage_receipt("not-a-digest", b"transform:x").is_err()
    );
    assert!(eliot_source_assurance::append_lineage_receipt(&previous, b"").is_err());
}
