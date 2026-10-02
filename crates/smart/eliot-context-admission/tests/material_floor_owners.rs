//! Owner-input producer fixtures for the #1742 material floor gate.
//!
//! These cover the producer side of the gate, not the compiler: one decision
//! whose owner facts are all present, and the two ways a decision that is
//! missing an owner fact is refused. The producer is
//! `eliot_context_admission::owner_material_inputs`; the gate it feeds
//! (`admit_material_decision`, `admit_material_resume`) keeps its own proofs.

#![allow(
    clippy::expect_used,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;

use eliot_agent_contracts::{AgentAttemptId, PublicReference, RevisionId, TargetId};
use eliot_authority::ImpactClass;
use eliot_context_admission::{
    AllowedFloorAction, FloorEvidenceStatus, OperationOwnerInputs, OwnerLineageRecords,
    owner_material_inputs,
};
use eliot_context_contracts::{
    AtomAvailability, CapacityLimits, ContextBinding, DecisionLineageActionContractRef,
    DecisionLineageAuthorization, DecisionLineageCompleteness, DecisionLineageEffect,
    DecisionLineageEpochRefs, DecisionLineageExpectedObservable, DecisionLineagePhase,
    DecisionLineageRef, DecisionLineageReferenceKind, DecisionLineageSlot,
    DecisionLineageSupersession, DecisionLineageVerifier, DecisionRevision, DecisionSafetyFloor,
    LossPolicy, MeasurementRef, ProviderDisposition, ProviderId, ProviderRole,
    ProviderRoleDenominator, RepresentationKind, RoleLossRule, SafetyFloorIdentity,
    SafetyFloorMember, SemanticRole,
};
use eliot_contracts::{
    ArtifactId, ContractId, ContractVersion, DecisionId, EpochId, EpochLineageId, OperationId,
    RequestId, ResourceGeneration, StateFence, TaskId, TaskRevision,
};
use eliot_receipts::{
    AuthorityBinding, EffectClass, OperationBinding, ProofCeiling, TaskBinding, VerifierBinding,
    WorkScopeId,
};

/// Owner-resolved reference strings this fixture presents. They are owner-issued
/// identities compared verbatim by the shared check; they decide nothing.
const GOVERNANCE_PROFILE: &str = "material-governance-profile";
const AUTHORITY_REF: &str = "material-authority-grant";
const INAPPLICABLE_REASON: &str =
    "the owner-issued policy declares this relation inapplicable for this decision";

fn artifact(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact id")
}

fn digest(byte: u8) -> String {
    char::from(byte).to_string().repeat(64)
}

fn epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
}

fn fence() -> StateFence {
    let mut fence = StateFence::new(epoch(), ResourceGeneration::new(1).expect("generation"));
    fence.task_revision = Some(TaskRevision::new(1).expect("task revision"));
    fence
}

fn provider_role(provider: &str, role: SemanticRole) -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new(provider).expect("provider"),
        role,
    }
}

/// The `PublicReference` wire kind each closed lineage category uses.
///
/// The mapping is the contract's own `DecisionLineageReferenceKind` wire
/// spelling; a fixture that disagreed with it would fail validation, which is
/// exactly what these cases are asserting is enforced.
fn wire_kind(kind: DecisionLineageReferenceKind) -> &'static str {
    match kind {
        DecisionLineageReferenceKind::Goal => "goal",
        DecisionLineageReferenceKind::Acceptance => "acceptance",
        DecisionLineageReferenceKind::Observation => "observation",
        DecisionLineageReferenceKind::Evidence => "evidence",
        DecisionLineageReferenceKind::EpistemicPosition => "epistemic_position",
        DecisionLineageReferenceKind::MaterialUnknown => "material_unknown",
        DecisionLineageReferenceKind::Rival => "rival",
        DecisionLineageReferenceKind::RejectionReason => "rejection_reason",
        DecisionLineageReferenceKind::SelectedOption => "selected_option",
        DecisionLineageReferenceKind::Rationale => "rationale",
        DecisionLineageReferenceKind::WhyNow => "why_now",
        DecisionLineageReferenceKind::RevisitCondition => "revisit_condition",
        DecisionLineageReferenceKind::ActionContract => "action_contract",
        DecisionLineageReferenceKind::AuthoritySource => "authority",
        DecisionLineageReferenceKind::ExpectedObservable => "expected_observable",
        DecisionLineageReferenceKind::VerifierContract => "verifier",
        DecisionLineageReferenceKind::Diff => "diff",
        DecisionLineageReferenceKind::ChangeObservation => "change_observation",
        DecisionLineageReferenceKind::ReviewItem => "review_item",
        DecisionLineageReferenceKind::ReviewDisposition => "review_disposition",
        DecisionLineageReferenceKind::ArtifactSource => "artifact_source",
        DecisionLineageReferenceKind::Outcome => "outcome",
        DecisionLineageReferenceKind::MemoryRevision => "memory_revision",
        DecisionLineageReferenceKind::OmissionManifest => "omission_manifest",
        DecisionLineageReferenceKind::HandoffArtifact => "handoff_artifact",
        DecisionLineageReferenceKind::Policy => "policy",
        DecisionLineageReferenceKind::UnknownEvidence => "evidence",
        DecisionLineageReferenceKind::Successor => "successor",
    }
}

fn lineage_ref(kind: DecisionLineageReferenceKind, target: &str) -> DecisionLineageRef {
    DecisionLineageRef {
        kind,
        reference: PublicReference {
            kind: wire_kind(kind).to_owned(),
            id: TargetId::new(target).expect("target id"),
            revision: RevisionId::new("r1").expect("revision id"),
            digest: None,
        },
    }
}

fn present<T>(value: T) -> DecisionLineageSlot<T> {
    DecisionLineageSlot::Present { value }
}

fn inapplicable<T>(policy: &str) -> DecisionLineageSlot<T> {
    DecisionLineageSlot::NotApplicable {
        policy: lineage_ref(DecisionLineageReferenceKind::Policy, policy),
        reason: INAPPLICABLE_REASON.to_owned(),
    }
}

fn deferred<T>(policy: &str, reason: &str) -> DecisionLineageSlot<T> {
    DecisionLineageSlot::NotYetProduced {
        policy: lineage_ref(DecisionLineageReferenceKind::Policy, policy),
        due_by: DecisionLineagePhase::Verification,
        reason: reason.to_owned(),
    }
}

/// One owner-resolved material decision and the owner records it published.
struct OwnerDecision {
    fence: StateFence,
    decision_id: DecisionId,
    task_id: TaskId,
    acceptance_revision: TaskRevision,
    resources: BTreeSet<String>,
    rule_evidence: ArtifactId,
    binding: ContextBinding,
}

impl OwnerDecision {
    fn owners(&self) -> OperationOwnerInputs<'_> {
        OperationOwnerInputs {
            decision_id: &self.decision_id,
            state_fence: &self.fence,
            impact_class: ImpactClass::Material,
            task_id: &self.task_id,
            acceptance_revision: self.acceptance_revision,
            requested_resources: &self.resources,
            governance_profile_ref: GOVERNANCE_PROFILE,
            authority_ref: AUTHORITY_REF,
            phase: DecisionLineagePhase::BeforeEffect,
            rule_evidence: self.rule_evidence.clone(),
        }
    }

    /// The floor identity the Context owner publishes for this decision
    /// boundary: two mandatory members, one of which the owner declares as the
    /// other's interpretation dependency.
    fn published_floor(&self) -> SafetyFloorIdentity {
        let goal = provider_role("goal-provider", SemanticRole::Goal);
        let evidence = provider_role("evidence-provider", SemanticRole::Evidence);
        let capacity = CapacityLimits {
            route_capacity: 4096,
            fixed_overhead: 128,
            output_reserve: 64,
            review_reserve: 64,
        };
        SafetyFloorIdentity {
            floor_id: self.rule_evidence.clone(),
            decision: DecisionRevision {
                decision_id: self.decision_id.clone(),
                recipe_revision: self.acceptance_revision,
                policy_sha256: digest(b'a'),
            },
            floor: DecisionSafetyFloor {
                binding: self.binding.clone(),
                mandatory_atoms: vec![artifact("atom-goal"), artifact("atom-evidence")],
                mandatory_roles: vec![SemanticRole::Goal, SemanticRole::Evidence],
                providers: ProviderRoleDenominator {
                    requested: vec![goal.clone(), evidence.clone()],
                    dispositions: vec![
                        ProviderDisposition {
                            slot: goal,
                            state: AtomAvailability::PresentCurrent,
                            evidence: None,
                        },
                        ProviderDisposition {
                            slot: evidence,
                            state: AtomAvailability::PresentCurrent,
                            evidence: None,
                        },
                    ],
                },
                members: vec![
                    SafetyFloorMember {
                        atom_id: artifact("atom-goal"),
                        role: SemanticRole::Goal,
                        availability: AtomAvailability::PresentCurrent,
                        measurement: Some(measurement()),
                        required_dependencies: vec![artifact("atom-evidence")],
                    },
                    SafetyFloorMember {
                        atom_id: artifact("atom-evidence"),
                        role: SemanticRole::Evidence,
                        availability: AtomAvailability::PresentCurrent,
                        measurement: Some(measurement()),
                        required_dependencies: Vec::new(),
                    },
                ],
                interpretation_dependencies: Vec::new(),
                rule_evidence: self.rule_evidence.clone(),
                capacity,
            },
        }
    }

    /// Every `I12.31` relation its owners issued for this decision before the
    /// effect is dispatched.
    fn lineage_records(&self) -> OwnerLineageRecords {
        let proposal = self.proposal();
        let expected = DecisionLineageExpectedObservable {
            observable: lineage_ref(
                DecisionLineageReferenceKind::ExpectedObservable,
                "expected-observable",
            ),
            verifier: lineage_ref(
                DecisionLineageReferenceKind::VerifierContract,
                "verifier-contract",
            ),
        };
        OwnerLineageRecords {
            goal: Some(present(lineage_ref(
                DecisionLineageReferenceKind::Goal,
                "governing-goal",
            ))),
            acceptance: Some(present(vec![lineage_ref(
                DecisionLineageReferenceKind::Acceptance,
                "acceptance-criterion",
            )])),
            task: Some(present(TaskBinding {
                task_id: self.task_id.clone(),
                task_revision: self.acceptance_revision,
                state_fence: self.fence.clone(),
            })),
            observations: Some(present(vec![lineage_ref(
                DecisionLineageReferenceKind::Observation,
                "boundary-observation",
            )])),
            evidence: Some(present(vec![lineage_ref(
                DecisionLineageReferenceKind::Evidence,
                "source-evidence",
            )])),
            epistemic_position: Some(present(lineage_ref(
                DecisionLineageReferenceKind::EpistemicPosition,
                "epistemic-position",
            ))),
            material_unknowns: Some(inapplicable("policy-material-unknowns")),
            rivals: Some(inapplicable("policy-rivals")),
            selected_option: Some(present(lineage_ref(
                DecisionLineageReferenceKind::SelectedOption,
                "selected-option",
            ))),
            rationale: Some(present(lineage_ref(
                DecisionLineageReferenceKind::Rationale,
                "decision-rationale",
            ))),
            why_now: Some(present(lineage_ref(
                DecisionLineageReferenceKind::WhyNow,
                "why-now",
            ))),
            revisit_conditions: Some(inapplicable("policy-revisit-conditions")),
            context: self.binding.clone(),
            action_contract: Some(present(DecisionLineageActionContractRef {
                reference: lineage_ref(
                    DecisionLineageReferenceKind::ActionContract,
                    "action-contract",
                ),
            })),
            effects: vec![DecisionLineageEffect {
                proposal: present(proposal.clone()),
                authorization: present(DecisionLineageAuthorization {
                    source: lineage_ref(
                        DecisionLineageReferenceKind::AuthoritySource,
                        "authority-source",
                    ),
                    binding: AuthorityBinding {
                        authority_id: ContractId::new("material-authority").expect("authority"),
                        authority_owner: "governor-action-model".to_owned(),
                        authority_epoch: self.fence.authority_epoch.clone(),
                        state_fence: self.fence.clone(),
                        allowed_effect: EffectClass::ReversibleMutation,
                        proof_ceiling: ProofCeiling::Observation,
                    },
                }),
                expected_observable: present(expected.clone()),
                // The execution and outcome receipts do not exist yet: the owner
                // defers them to verification rather than the producer
                // fabricating a receipt or defaulting the relation away.
                execution: Some(deferred(
                    "policy-execution",
                    "the operation receipt is due once the effect has been issued",
                )),
                outcome: Some(deferred(
                    "policy-outcome",
                    "the outcome receipt is due at verification",
                )),
            }],
            operations: Some(present(vec![proposal])),
            diffs: Some(inapplicable("policy-diffs")),
            change_observations: Some(inapplicable("policy-change-observations")),
            anchors: Some(inapplicable("policy-anchors")),
            reviews: Some(inapplicable("policy-reviews")),
            artifacts: Some(inapplicable("policy-artifacts")),
            verifiers: Some(present(vec![DecisionLineageVerifier {
                binding: VerifierBinding {
                    verifier_id: ContractId::new("material-verifier").expect("verifier"),
                    verifier_revision: ContractVersion::new(1, 0, 0),
                    artifact_ids: vec![artifact("verifier-artifact")],
                    proof_ceiling: ProofCeiling::Observation,
                    state_fence: self.fence.clone(),
                },
                source: expected.verifier,
            }])),
            outcomes: Some(inapplicable("policy-outcomes")),
            memory_revisions: Some(inapplicable("policy-memory-revisions")),
            omissions: Some(inapplicable("policy-omissions")),
            handoff: Some(inapplicable("policy-handoff")),
            epoch: Some(DecisionLineageEpochRefs {
                authority_epoch: self.fence.authority_epoch.clone(),
                state_fence: self.fence.clone(),
                supersession: DecisionLineageSupersession::Current {
                    policy: lineage_ref(
                        DecisionLineageReferenceKind::Policy,
                        "policy-no-supersession",
                    ),
                },
            }),
        }
    }

    fn proposal(&self) -> OperationBinding {
        OperationBinding {
            operation_id: OperationId::new("material-operation").expect("operation"),
            request_id: RequestId::new("material-request").expect("request"),
            idempotency_key: "material-operation-once".to_owned(),
            operation_kind: "act".to_owned(),
            effect: EffectClass::ReversibleMutation,
            state_fence: self.fence.clone(),
        }
    }
}

fn measurement() -> MeasurementRef {
    MeasurementRef {
        digest: digest(b'c'),
        serializer: "json-v1".to_owned(),
    }
}

/// One owner-resolved material decision, at its own fence and acceptance
/// revision, with the owner records it published for that boundary.
fn owner_decision() -> OwnerDecision {
    let state_fence = fence();
    let decision_id = DecisionId::new("material-decision").expect("decision");
    let task_id = TaskId::new("material-task").expect("task");
    OwnerDecision {
        binding: ContextBinding {
            task_id: task_id.clone(),
            attempt_id: AgentAttemptId::new("material-attempt").expect("attempt"),
            scope_id: WorkScopeId::new("material-scope").expect("scope"),
            state_fence: state_fence.clone(),
            decision_id: decision_id.clone(),
            operation_id: None,
        },
        fence: state_fence,
        decision_id,
        task_id,
        acceptance_revision: TaskRevision::new(1).expect("task revision"),
        resources: BTreeSet::from(["repo:crates/smart".to_owned()]),
        rule_evidence: artifact("material-floor-rule"),
    }
}

/// A decision with real owner facts produces the two gate arguments, and the
/// phase-aware contract reads the produced lineage as complete.
#[test]
fn owner_material_inputs_carries_published_floor_and_issued_lineage() {
    let decision = owner_decision();
    let owners = decision.owners();
    let produced = owner_material_inputs(
        &owners,
        &decision.published_floor(),
        decision.lineage_records(),
    )
    .expect("owner facts are complete");

    // One policy per published floor member, in the owner's own member order,
    // with the owner's own dependency edge and the strict delivery rule.
    assert_eq!(produced.policies.len(), 2);
    assert_eq!(produced.policies[0].atom_id, artifact("atom-goal"));
    assert_eq!(produced.policies[0].role, SemanticRole::Goal);
    assert_eq!(produced.policies[0].required_dependencies, vec![artifact("atom-evidence")]);
    assert_eq!(produced.policies[1].atom_id, artifact("atom-evidence"));
    assert!(produced.policies[1].required_dependencies.is_empty());
    for policy in &produced.policies {
        assert_eq!(policy.loss_policy, LossPolicy::NonDroppable);
        assert_eq!(policy.allowed_representations, vec![RepresentationKind::Whole]);
        // The applicability key is the owner-resolved impact class, never a
        // caller claim, and never an empty set that could never enter a floor.
        assert_eq!(policy.applicable_impact_classes, vec![ImpactClass::Material]);
    }
    // The gate accepts each produced policy on its own terms: the shared
    // loss-policy authority validates the declaration, and the applicability
    // key is the class the owner resolved for this operation.
    for policy in &produced.policies {
        RoleLossRule {
            role: policy.role,
            loss_policy: policy.loss_policy,
            required: true,
            allowed_representations: policy.allowed_representations.clone(),
        }
        .validate()
        .expect("the produced policy satisfies the shared loss-policy authority");
        assert!(policy.applicable_impact_classes.contains(&owners.impact_class));
    }

    // The lineage is exactly what the owners issued, and it is complete for the
    // phase it was produced for: completeness stays the contract's decision.
    assert_eq!(
        produced
            .lineage
            .validate_for_phase(owners.phase)
            .expect("assembled lineage validates"),
        DecisionLineageCompleteness::Complete
    );
    assert_eq!(produced.lineage.context.decision_id, decision.decision_id.clone());
    assert_eq!(produced.lineage.effects.len(), 1);
}

/// A floor published for a rule this decision does not name is refused with the
/// exact typed limitation naming that reference, and no policy is produced.
#[test]
fn owner_material_inputs_refuses_unnamed_published_floor_rule() {
    let decision = owner_decision();
    let mut owners = decision.owners();
    owners.rule_evidence = artifact("other-floor-rule");
    let mut published = decision.published_floor();
    published.floor_id = decision.rule_evidence.clone();

    let refusal = owner_material_inputs(&owners, &published, decision.lineage_records())
        .expect_err("a floor rule this decision does not name is refused");
    let refusal = refusal
        .incomplete()
        .expect("the refusal is the typed DECISION_CONTEXT_INCOMPLETE limitation");
    assert_eq!(refusal.evidence_status, FloorEvidenceStatus::OwnerPolicyMissing);
    assert_eq!(refusal.allowed_action, AllowedFloorAction::Refresh);
    // The exact reference the decision must name is the gap identity.
    assert_eq!(
        refusal.incomplete.missing,
        vec![decision.rule_evidence.clone()]
    );
    assert!(refusal.missing_owner.is_some());
}

/// A relation no owner issued stays absent and is refused by name, rather than
/// becoming an empty set, a defaulted disposition or a fabricated record.
#[test]
fn owner_material_inputs_refuses_absent_lineage_relation() {
    let decision = owner_decision();
    let owners = decision.owners();
    let mut records = decision.lineage_records();
    records.rationale = None;

    let refusal = owner_material_inputs(&owners, &decision.published_floor(), records)
        .expect_err("an unissued lineage relation is refused");
    let refusal = refusal
        .incomplete()
        .expect("the refusal is the typed DECISION_CONTEXT_INCOMPLETE limitation");
    assert_eq!(refusal.evidence_status, FloorEvidenceStatus::LineageIncomplete);
    assert_eq!(refusal.allowed_action, AllowedFloorAction::Expand);
    assert_eq!(refusal.phase, DecisionLineagePhase::BeforeEffect);
    assert_eq!(
        refusal.incomplete.missing,
        vec![decision.rule_evidence.clone()]
    );
    assert!(refusal.missing_owner.is_some());
    assert!(
        refusal
            .incomplete
            .reopening_requirements
            .iter()
            .any(|requirement| requirement.contains("rationale")),
        "the refusal names the exact unissued relation: {:?}",
        refusal.incomplete.reopening_requirements
    );
}

