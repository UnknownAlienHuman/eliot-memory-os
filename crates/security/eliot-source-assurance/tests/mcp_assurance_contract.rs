#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_source_assurance::{
    AdmissibleUse, AdmissionExpectation, AdmissionOutcome, AxisStatus, EffectCeiling,
    GoverningSourceIdentity, GoverningSourceSet, InstructionTaint, OwnerSourceEvidence,
    PrivacyClass, QuarantineStatus, ScopeBindingProof, SourceAssurance, SourceAssurancePolicy,
    SourceFrontierBinding, SourceProvenance, SourceSnapshotBinding, SourceTrustProfile,
    ThreatStatus, TrustAxis,
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
                canonical_ref: "docs/architecture.md".into(),
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
