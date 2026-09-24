//! Production Governor consumer for durable authority-revocation evidence.
//!
//! This is the semantic fan-out seam. The store supplies only the durable
//! closure record; this module walks the explicit influence edges, evaluates
//! the current influence ceiling, recompiles the current context projection,
//! and returns the exact invalidation/rebuild obligations to the owning
//! composition. It never edits historical records or treats similarity as
//! lineage.

use std::collections::BTreeSet;

use eliot_authority::RevocationHistoryEvidence;
use eliot_context::{
    CompiledContext, ContextAtom, ContextCompiler, ContextInput, ContextRecipe,
    minimum_assertability_for_lineage, revoked_derivative_invalidation_set,
};
use eliot_contracts::{ArtifactId, StateFence, TaskRevision};
use eliot_evidence::{Assertability, EpistemicStatus, EvidenceFreshness};
use eliot_influence::{
    self, InfluenceDecision, InfluenceEdge, InfluenceLevel, InfluencePolicy, InfluenceRequest,
    ProvenanceRecord, decide, traverse_dependency_closure,
};
use eliot_problem::{
    OwnerRef, Problem, ProblemId, ProblemState, RevocationQuarantine, RevocationRebuildOrder,
    SignalId,
};
use eliot_security_contracts::{
    CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, IndependenceLevel,
    InfluenceDependencyClosure, InfluenceState, InstructionTaint, IntegrityStatus, PrivacyClass,
    QuarantineState, SourceAssurance,
};

use crate::CompositionError;

/// Rebuildable derivative invalidation ledger owned by the Governor
/// composition. It records exact cache/context/module-profile keys removed
/// from service; it never becomes canonical memory or authority.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevocationInvalidationLedger {
    invalidated_keys: BTreeSet<String>,
}

impl RevocationInvalidationLedger {
    /// Invalidates the exact keys returned by the context compiler fan-out.
    pub fn invalidate(&mut self, keys: &BTreeSet<String>) {
        self.invalidated_keys.extend(keys.iter().cloned());
    }

    /// Returns the current invalidated-key projection.
    #[must_use]
    pub fn keys(&self) -> &BTreeSet<String> {
        &self.invalidated_keys
    }
}

/// One current semantic claim whose support may be removed by a revocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationClaim {
    /// Stable current justification, plan, or answer identity.
    pub id: String,
    /// Exact material supports for the claim.
    pub support_refs: BTreeSet<String>,
}

/// Input to one production revocation fan-out pass.
#[derive(Clone, Debug)]
pub struct RevocationFanoutInput {
    /// The committed history read from the canonical store.
    pub history: RevocationHistoryEvidence,
    /// Explicit source→dependent edges. Similarity is never used as an edge.
    pub graph: Vec<InfluenceEdge>,
    /// Current admitted context input for the active compiled projection.
    pub context: ContextInput,
    /// Exact recipe bound to `context`.
    pub recipe: ContextRecipe,
    /// Current claims/justifications/plans to contest when dependent.
    pub current_claims: Vec<RevocationClaim>,
}

/// Result of one fan-out pass. The caller consumes the keys and rebuild order;
/// the historical receipt remains untouched.
#[derive(Clone, Debug)]
pub struct RevocationFanoutResult {
    /// Union of all explicit closure traversals, including roots.
    pub affected_refs: BTreeSet<String>,
    /// Context compiled after revoked support was removed/downgraded.
    pub compiled_context: CompiledContext,
    /// Exact cache/context-profile/module-profile invalidation keys.
    pub invalidation_keys: BTreeSet<String>,
    /// Current claims made contestable/reopened by support membership.
    pub contested_claims: Vec<String>,
    /// Bounded Problem State quarantine/rebuild orders.
    pub rebuild_orders: Vec<RevocationRebuildOrder>,
    /// Minimum current assertability across the supplied material lineage.
    pub minimum_lineage_assertability: Assertability,
    /// Production influence decisions proving the minimum ceiling was applied.
    pub influence_decisions: Vec<InfluenceDecision>,
}

impl RevocationFanoutResult {
    /// Returns the exact invalidation keys for a cache/profile owner.
    #[must_use]
    pub fn invalidation_keys(&self) -> &BTreeSet<String> {
        &self.invalidation_keys
    }
}

/// Applies one committed revocation history to current derived projections.
///
/// This function is intentionally called by the live owner-feed route, not by
/// unit tests. Every operation is a pure projection over the supplied current
/// context/claims; the caller persists the durable Problem/rebuild order
/// through its owning transition path.
#[allow(
    clippy::too_many_lines,
    reason = "the fan-out deliberately keeps the causal projection stages together"
)]
pub fn apply_revocation_fanout(
    input: &RevocationFanoutInput,
) -> Result<RevocationFanoutResult, CompositionError> {
    if input.history.state_fence != input.context.state_fence {
        return Err(CompositionError::Recovery(
            "revocation history and current context fences disagree".to_owned(),
        ));
    }
    if input.recipe.recipe_revision != input.context.task_revision {
        return Err(CompositionError::Recovery(
            "revocation fan-out context recipe is stale".to_owned(),
        ));
    }

    let mut affected_refs = BTreeSet::new();
    let mut revoked_handles = BTreeSet::new();
    let mut quarantined_atoms = BTreeSet::new();
    let mut invalidation_keys = BTreeSet::new();
    let mut influence_decisions = Vec::new();

    for closure in &input.history.closures {
        validate_closure(closure, &input.history)?;
        let traversed = traverse_dependency_closure(&closure.root_ref, &input.graph);
        for reference in &traversed {
            affected_refs.insert(reference.clone());
            let handle = ArtifactId::new(reference).map_err(|error| {
                CompositionError::Owner(format!("revocation handle is invalid: {error}"))
            })?;
            revoked_handles.insert(handle);
        }
        for atom in &input.context.atoms {
            if atom.source_handles.iter().any(|handle| {
                handle.as_str() == closure.root_ref
                    || closure
                        .dependent_refs
                        .iter()
                        .any(|ref_| ref_ == handle.as_str())
            }) {
                quarantined_atoms.insert(atom.atom_id.clone());
            }
        }
        let decision = influence_decision(closure, &traversed)?;
        influence_decisions.push(decision);
    }

    let compiled_context =
        ContextCompiler::compile_with_revocation(&input.context, &input.recipe, &revoked_handles)
            .map_err(|error| {
            CompositionError::Recovery(format!("revocation context recompile failed: {error}"))
        })?;

    invalidation_keys.extend(revoked_derivative_invalidation_set(
        &revoked_handles,
        &quarantined_atoms,
    ));
    let minimum_lineage_assertability = current_mixed_lineage_ceiling(
        &input
            .context
            .atoms
            .iter()
            .map(|atom| atom.assertability)
            .collect::<Vec<_>>(),
    );

    let mut contested_claims = Vec::new();
    for claim in &input.current_claims {
        if claim
            .support_refs
            .iter()
            .any(|support| affected_refs.contains(support))
        {
            contested_claims.push(claim.id.clone());
        }
    }
    contested_claims.sort();
    contested_claims.dedup();

    let mut rebuild_orders = Vec::new();
    for closure in &input.history.closures {
        let traversed = traverse_dependency_closure(&closure.root_ref, &input.graph);
        let impacted_scope = closure.root_ref.clone();
        let impacted_scopes = traversed;
        let evidence = ArtifactId::new(format!("revocation-evidence:{}", closure.closure_id))
            .map_err(|error| {
                CompositionError::Owner(format!("revocation evidence is invalid: {error}"))
            })?;
        let mut problem = Problem {
            problem_id: ProblemId::new(format!("problem:revocation:{}", closure.closure_id))
                .map_err(|error| CompositionError::Owner(error.to_string()))?,
            signal_refs: vec![
                SignalId::new(format!("signal:revocation:{}", closure.closure_id))
                    .map_err(|error| CompositionError::Owner(error.to_string()))?,
            ],
            title: "Revoked lineage requires clean-input rebuild".to_owned(),
            scope_id: impacted_scope.clone(),
            owner: OwnerRef {
                principal: "governor:revocation".to_owned(),
                generation: "current-authority-epoch".to_owned(),
            },
            state: ProblemState::Open,
            evidence_refs: vec![evidence.clone()],
            resolution_condition: "rebuild from clean inputs and pass current requalification"
                .to_owned(),
            acknowledged_by: None,
            state_fence: input.context.state_fence.clone(),
            revision: 1,
            reopen_count: 0,
        };
        let request = RevocationQuarantine {
            impacted_scopes,
            revocation_evidence: vec![evidence],
            revoked_source_ref: closure.root_ref.clone(),
            rebuild_condition: "rebuild_from_clean_inputs".to_owned(),
        };
        let order = problem
            .open_for_revocation(&input.context.state_fence, &request)
            .map_err(|error| {
                CompositionError::Recovery(format!("revocation Problem State failed: {error}"))
            })?;
        rebuild_orders.push(order);
    }

    Ok(RevocationFanoutResult {
        affected_refs,
        compiled_context,
        invalidation_keys,
        contested_claims,
        rebuild_orders,
        minimum_lineage_assertability,
        influence_decisions,
    })
}

fn validate_closure(
    closure: &InfluenceDependencyClosure,
    history: &RevocationHistoryEvidence,
) -> Result<(), CompositionError> {
    closure.validate().map_err(|error| {
        CompositionError::Recovery(format!("revocation closure is invalid: {error}"))
    })?;
    if closure.state_fence != history.state_fence
        || closure.revision != history.source_revision
        || closure.current_influence != InfluenceState::Revoked
        || closure.invalidation_reason.is_none()
    {
        return Err(CompositionError::Recovery(
            "revocation closure is not CURRENT terminal evidence".to_owned(),
        ));
    }
    Ok(())
}

fn influence_decision(
    closure: &InfluenceDependencyClosure,
    affected: &[String],
) -> Result<InfluenceDecision, CompositionError> {
    let fence = closure.state_fence.clone();
    let subject = format!("derived:{}", closure.root_ref);
    let request = InfluenceRequest {
        request_id: format!("revocation-fanout:{}", closure.closure_id),
        subject_ref: subject.clone(),
        requested_level: InfluenceLevel::VerifiedUse,
        policy: InfluencePolicy {
            policy_id: "policy:revocation-fanout".to_owned(),
            revision: 1,
            state_fence: fence.clone(),
            require_verified_integrity: false,
            require_current_freshness: false,
            allow_unknown_independence: true,
            allow_instruction_taint: true,
            minimum_level: InfluenceLevel::Stored,
        },
        provenance: ProvenanceRecord {
            subject_ref: subject,
            origin_ref: closure.root_ref.clone(),
            source_assurance: SourceAssurance {
                source_ref: closure.root_ref.clone(),
                provenance_ref: format!("revocation:{}", closure.closure_id),
                integrity: IntegrityStatus::Verified,
                freshness: FreshnessStatus::Current,
                competence: CompetenceLevel::DomainVerified,
                independence: IndependenceLevel::Independent,
                privacy_class: PrivacyClass::Public,
                instruction_taint: InstructionTaint::Cleared,
                allowed_epistemic_use: vec![EpistemicUse::Observation],
                allowed_effects: vec![EffectCeiling::ReadOnly],
                required_verifier: None,
                quarantine: QuarantineState::None,
                state_fence: fence.clone(),
            },
            parent_refs: affected.to_vec(),
            transformation_ref: Some(format!("revocation:{}", closure.closure_id)),
            state_fence: fence,
        },
        dependency_closure: closure.clone(),
    };
    decide(&request)
        .map_err(|error| CompositionError::Recovery(format!("influence decision failed: {error}")))
}

/// Computes the weakest current assertability over a mixed-lineage set.
#[must_use]
pub fn current_mixed_lineage_ceiling(levels: &[Assertability]) -> Assertability {
    minimum_assertability_for_lineage(levels)
}

/// Builds a small, valid context projection for an owner feed that has no
/// materialized view yet. The production feed uses this only as a bounded
/// cache-rebuild target; the compiler still receives the real revoked handles
/// and returns an empty/quarantined active view.
pub fn revocation_cache_input(
    fence: StateFence,
    scope: &str,
    affected_refs: &BTreeSet<String>,
) -> Result<(ContextInput, ContextRecipe), CompositionError> {
    let task_revision = TaskRevision::genesis();
    let atoms = affected_refs
        .iter()
        .map(|reference| {
            let handle = ArtifactId::new(reference.clone()).map_err(|error| {
                CompositionError::Owner(format!("revocation cache handle is invalid: {error}"))
            })?;
            Ok(ContextAtom {
                atom_id: ArtifactId::new(format!("cache-atom:{reference}")).map_err(|error| {
                    CompositionError::Owner(format!("revocation cache atom is invalid: {error}"))
                })?,
                role: eliot_context::ContextRole::Evidence,
                payload: format!("revoked support {reference}"),
                source_handles: vec![handle],
                status: EpistemicStatus::Supported,
                assertability: Assertability::Assertable,
                freshness: EvidenceFreshness::ExactCandidate,
                state_fence: fence.clone(),
                required: false,
                protected: false,
                cost: 1,
                expected_decision_delta: 0,
                risk: 0,
                cues: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>, CompositionError>>()?;
    let input = ContextInput {
        scope: scope.to_owned(),
        task_id: None,
        task_revision,
        state_fence: fence,
        atoms,
        unknowns: Vec::new(),
    };
    let recipe = ContextRecipe {
        recipe_revision: task_revision,
        total_cost: u32::MAX,
        role_budgets: vec![eliot_context::RoleBudget {
            role: eliot_context::ContextRole::Evidence,
            maximum_cost: u32::MAX,
        }],
        required_roles: Vec::new(),
    };
    Ok((input, recipe))
}
