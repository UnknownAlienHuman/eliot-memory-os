#![allow(
    clippy::expect_used,
    reason = "deterministic fixture constructors use static valid identifiers and fail fast"
)]

use std::collections::BTreeSet;

use eliot_contracts::{ContractId, ContractVersion, SourceId};
use eliot_dreamer_contracts::{
    AffordanceTarget, BranchEvidenceAcceptance, BudgetDemand, ConditionAssumptionRef,
    MaterialClaimRef, PossibleResultSchema, ProbeAffordanceSemantics, ProbeCapabilityAvailability,
    ProbeExternalOwners, ProbeLifecycle, ProbeObjectiveBinding, ProbeObjectiveMateriality,
    ProbeObjectiveRef, ProbeObjectiveResolution, ProbeOwnerRef, ResultBranch,
    ResultBranchAcceptance, grounding::canonical::ArtifactId,
};
use eliot_evaluation_contracts::{ExpectedObservableSpec, PlannedVerifierRef};
use eliot_receipts::ProofCeiling;

pub fn digest(seed: &str) -> String {
    eliot_dreamer_contracts::grounding::canonical::sha256_hex(seed.as_bytes())
}

pub fn artifact(id: &str) -> ArtifactId {
    ArtifactId::new(id).expect("test artifact id")
}

pub fn objective_for(id: &str) -> ProbeObjectiveRef {
    ProbeObjectiveRef {
        objective_id: artifact(id),
        objective_digest: digest(id),
    }
}

pub fn verifier() -> PlannedVerifierRef {
    PlannedVerifierRef {
        verifier_id: ContractId::new("probe-verifier").expect("test verifier id"),
        scope: "scope-1".to_owned(),
        verifier_config_hash: digest("probe-verifier-config"),
        expected_observable: ExpectedObservableSpec {
            property: "bounded result branch".to_owned(),
            matcher: "declared branch matcher".to_owned(),
            artifact_selector: "retained-source".to_owned(),
        },
        environment_binding: "candidate-only".to_owned(),
        verifier_authority_ref: "contract-owner".to_owned(),
        contract_revision: ContractVersion::new(1, 0, 0),
        proof_ceiling: ProofCeiling::CandidateArtifact,
    }
}

pub fn branch_acceptance(branches: &[ResultBranch]) -> Vec<ResultBranchAcceptance> {
    branches
        .iter()
        .map(|branch| ResultBranchAcceptance {
            result_id: branch.result_id.clone(),
            evidence: BranchEvidenceAcceptance::Accepted {
                owner: ProbeOwnerRef::Source {
                    owner: SourceId::new("probe-evidence").expect("test source id"),
                },
                source_refs: BTreeSet::from([artifact("probe-source")]),
                coverage: None,
                verifier: Box::new(verifier()),
            },
            causal: None,
        })
        .collect()
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the schema constructor consumes the owned branch vector after deriving acceptance"
)]
pub fn schema_with_acceptance(
    schema_id: &str,
    targets: Vec<eliot_dreamer_contracts::ResultTarget>,
    branches: Vec<ResultBranch>,
) -> PossibleResultSchema {
    PossibleResultSchema::new_with_acceptance(
        artifact(schema_id),
        targets,
        branches.clone(),
        branch_acceptance(&branches),
    )
    .expect("test result schema")
}

pub fn ready_semantics(target: &AffordanceTarget) -> Option<ProbeAffordanceSemantics> {
    let (objective, claim, assumption, denominator) = match target {
        AffordanceTarget::RivalPredictions { .. } => {
            (objective_for("ready-objective"), None, None, None)
        }
        AffordanceTarget::EvidenceGap { .. } => return None,
        AffordanceTarget::Assumption { assumption, claim } => (
            objective_for("ready-objective"),
            claim.clone(),
            Some(assumption.clone()),
            None,
        ),
        AffordanceTarget::Objective { objective } => (objective.clone(), None, None, None),
    };
    Some(ProbeAffordanceSemantics {
        objective_binding: Some(ProbeObjectiveBinding {
            objective,
            claim,
            assumption,
            materiality: ProbeObjectiveMateriality::Material {
                rationale: "load-bearing objective supplied by the owning contract".to_owned(),
            },
            resolution: ProbeObjectiveResolution::Open,
            denominator,
            causal_requirements: None,
        }),
        budget_demand: Some(BudgetDemand {
            input_bytes: Some(1),
            output_bytes: Some(1),
            source_width: Some(1),
            reference_width: Some(1),
            model_calls: Some(1),
            attempts: Some(1),
            candidates: Some(1),
            wall_ms: Some(1),
            work_fan_out: Some(1),
            report_bytes: Some(1),
            max_stu: Some(1),
        }),
        lifecycle: Some(ProbeLifecycle {
            cancellation: "consumer cancels before any effect".to_owned(),
            cleanup_rollback: "consumer cleans up or rolls back bounded state".to_owned(),
            reconciliation: "consumer reconciles unknown outcome before reuse".to_owned(),
            repeat: eliot_dreamer_contracts::ProbeRepeatRef {
                requirement_id: "probe-retry-contract".to_owned(),
                reason: "changed conditions require a fresh candidate".to_owned(),
            },
        }),
        external_owners: Some(ProbeExternalOwners {
            admission: ProbeOwnerRef::Source {
                owner: SourceId::new("probe-admission").expect("test source id"),
            },
            execution: ProbeOwnerRef::Source {
                owner: SourceId::new("probe-execution").expect("test source id"),
            },
            evidence: ProbeOwnerRef::Source {
                owner: SourceId::new("probe-evidence").expect("test source id"),
            },
            verifier: ProbeOwnerRef::Verifier {
                verifier_id: ContractId::new("probe-verifier").expect("test verifier id"),
            },
        }),
        capability: Some(ProbeCapabilityAvailability::Available {
            detail: "candidate capability is declared available by its owner".to_owned(),
        }),
    })
}

#[allow(dead_code)]
pub fn claim_assumption_binding(
    claim: Option<MaterialClaimRef>,
    assumption: Option<ConditionAssumptionRef>,
) -> (Option<MaterialClaimRef>, Option<ConditionAssumptionRef>) {
    (claim, assumption)
}
