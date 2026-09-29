//! Scorecard construction from actual compilation evidence (W3).
//!
//! Every result this module produces is derived from the exact admitted set,
//! the ordered rendered payload and the complete omission/expansion accounting
//! of the packet being compiled. It invokes no model, grades no semantic
//! claim of its own, and invents no identity, digest or measurement: each
//! dimension reads the members the compilation actually admitted, and a
//! dimension with no current observation is graded `Unknown` against its own
//! named missing evidence rather than a pass.
//!
//! The scorecard binds itself to the exact rendered output through
//! [`QualityScorecardBinding`]. The `rendered_payload_digest` it records is the
//! existing canonical payload digest of [`ActiveUnderstandingView`], computed
//! over `{schema_version, binding, recipe_digest, fence_digest, rendered}` and
//! therefore already excluding the scorecard from its own hash input. No new
//! digest scheme is introduced and no circular self-reference is created.

use std::collections::BTreeSet;

use eliot_context_contracts::{
    ActiveUnderstandingView, AdmittedContextSet, ContextBinding, ContextError, ContextRecipe,
    ProofCeiling, QUALITY_DIMENSIONS, QualityApplicability, QualityDimension,
    QualityDimensionResult, QualityDimensionState, QualityRuleRevision, QualityScorecard,
    QualityScorecardBinding, RenderedAtom, SemanticRole,
};
use eliot_contracts::ArtifactId;

/// The applicability inputs resolved before grading (W2).
///
/// The builder never resolves these itself: task/acceptance, route, impact,
/// Governance Profile, protected floor and active directives all arrive from
/// their own owners. An input an owner left unresolved is carried through as
/// [`QualityApplicability::Unknown`], which blocks the dependent action rather
/// than silently selecting the weakest profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualityApplicabilityInput {
    /// Whether the applicable task/acceptance relation was resolved.
    pub task_acceptance: Result<(), String>,
    /// Whether the route relation was resolved.
    pub route: Result<(), String>,
    /// Whether the impact relation was resolved.
    pub impact: Result<(), String>,
    /// Whether the Governance Profile was resolved.
    pub governance_profile: Result<(), String>,
    /// Whether the protected floor was resolved.
    pub protected_floor: Result<(), String>,
    /// Whether the active directives were resolved.
    pub active_directives: Result<(), String>,
    /// Per-dimension applicability a governing policy declared inapplicable,
    /// with the policy reason that makes it so.
    pub not_applicable: Vec<(QualityDimension, String)>,
}

impl QualityApplicabilityInput {
    /// Collapse the resolved inputs to the applicability of one dimension.
    fn resolve(&self) -> Result<(), String> {
        for (name, resolved) in [
            ("task/acceptance", &self.task_acceptance),
            ("route", &self.route),
            ("impact", &self.impact),
            ("governance_profile", &self.governance_profile),
            ("protected_floor", &self.protected_floor),
            ("active_directives", &self.active_directives),
        ] {
            if let Err(unresolved) = resolved {
                return Err(format!("{name}: {unresolved}"));
            }
        }
        Ok(())
    }

    /// Applicability of one dimension, honouring a policy-not-applicable entry.
    fn for_dimension(&self, dimension: QualityDimension) -> QualityApplicability {
        if let Some((_, reason)) = self
            .not_applicable
            .iter()
            .find(|(candidate, _)| *candidate == dimension)
        {
            return QualityApplicability::NotApplicable {
                reason: reason.clone(),
            };
        }
        match self.resolve() {
            Ok(()) => QualityApplicability::Resolved,
            Err(unresolved) => QualityApplicability::Unknown { unresolved },
        }
    }
}

/// The members a semantic role must contribute, taken from the protected floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualityRoleRequirement {
    /// The semantic role.
    pub role: SemanticRole,
    /// Members the protected floor declared mandatory for this role.
    pub required: Vec<ArtifactId>,
}

/// The compiler-side evidence the builder grades against.
///
/// Every field is the compilation's own accounting, supplied by the owner that
/// produced it. The builder re-derives coverage from these sets; it never
/// treats one representative atom per role as coverage of the whole member set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualityCompilationEvidence {
    /// Semantic roles whose members the grade must account for.
    pub required_roles: Vec<QualityRoleRequirement>,
    /// Atoms omitted or displaced, with the exact handle that reopens them.
    pub omission_handles: Vec<ArtifactId>,
    /// Source/evidence revisions the grade was taken against.
    pub evidence_revisions: Vec<ArtifactId>,
    /// Verifier/action contract identity for verifier readiness, when resolved.
    pub verifier_contract: Option<ArtifactId>,
    /// Task/model/requirement owner's supported decision facts, when supplied.
    pub supported_decision_facts: Option<ArtifactId>,
    /// Coherent-read evidence identity (#1729), when supplied.
    pub coherent_read_evidence: Option<ArtifactId>,
}

/// Exact identities of the output the scorecard grades.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualityOutputBindingInput {
    /// Recipe digest of this compilation.
    pub recipe_digest: String,
    /// Canonical digest of the admitted set that was rendered.
    pub admitted_set_digest: String,
    /// Canonical digest of the ordered rendered payload, excluding the
    /// scorecard by construction.
    pub rendered_payload_digest: String,
    /// Exact serializer identity that produced the payload.
    pub serializer_id: String,
    /// Exact route identity the payload was produced through.
    pub route_id: String,
}

/// Build the twelve-dimension scorecard for one compiled packet.
///
/// Returns one result for each member of [`QUALITY_DIMENSIONS`] in canonical
/// order, so a caller cannot omit a dimension and all twelve remain present.
pub fn build_scorecard(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    rendered: &[RenderedAtom],
    applicability: &QualityApplicabilityInput,
    evidence: &QualityCompilationEvidence,
    output: &QualityOutputBindingInput,
) -> Result<QualityScorecard, ContextError> {
    admitted.validate()?;
    if output.recipe_digest != recipe.recipe_sha256
        || admitted.economy.recipe_digest != recipe.recipe_sha256
    {
        return Err(ContextError::IdentityConflict);
    }
    if output.admitted_set_digest != admitted.canonical_payload_digest()? {
        return Err(ContextError::IdentityConflict);
    }
    // W4: grade the FINAL representation, not the pre-truncated candidate set.
    // The digest is the existing canonical one and excludes this scorecard.
    let fence_digest = eliot_context_contracts::canonical_fence_digest(&admitted.binding.state_fence)?;
    if output.rendered_payload_digest
        != ActiveUnderstandingView::canonical_output_digest(
            &admitted.binding,
            &recipe.recipe_sha256,
            &fence_digest,
            rendered,
        )?
    {
        return Err(ContextError::IdentityConflict);
    }
    let rule = QualityRuleRevision {
        recipe_revision: recipe.decision.recipe_revision,
        recipe_digest: recipe.recipe_sha256.clone(),
        profile_revision: applicability_profile_revision(evidence),
    };
    let results = QUALITY_DIMENSIONS
        .iter()
        .map(|dimension| {
            grade_dimension(
                *dimension,
                &GradingInputs {
                    binding: &admitted.binding,
                    rule: &rule,
                    applicability,
                    evidence,
                    rendered,
                },
            )
        })
        .collect();
    let scorecard = QualityScorecard {
        binding: admitted.binding.clone(),
        output: QualityScorecardBinding {
            recipe_digest: output.recipe_digest.clone(),
            admitted_set_digest: output.admitted_set_digest.clone(),
            rendered_payload_digest: output.rendered_payload_digest.clone(),
            serializer_id: output.serializer_id.clone(),
            route_id: output.route_id.clone(),
            evidence_revisions: evidence.evidence_revisions.clone(),
            omission_handles: evidence.omission_handles.clone(),
        },
        results,
    };
    scorecard.validate()?;
    // A4: the scorecard's own binding content is compared against the packet it
    // describes, with every expected value derived from the packet.
    scorecard.grades_output(
        &output.recipe_digest,
        &output.admitted_set_digest,
        &output.rendered_payload_digest,
        &output.serializer_id,
        &output.route_id,
        &evidence.omission_handles,
    )?;
    Ok(scorecard)
}

/// Governance Profile revision the grade was taken under.
fn applicability_profile_revision(evidence: &QualityCompilationEvidence) -> String {
    evidence
        .verifier_contract
        .as_ref()
        .map_or_else(|| "governance-profile-unresolved".to_owned(), ToString::to_string)
}

/// The shared compilation state every dimension is graded against.
struct GradingInputs<'a> {
    binding: &'a ContextBinding,
    rule: &'a QualityRuleRevision,
    applicability: &'a QualityApplicabilityInput,
    evidence: &'a QualityCompilationEvidence,
    rendered: &'a [RenderedAtom],
}

/// Grade one dimension from the compilation's actual member accounting.
fn grade_dimension(
    dimension: QualityDimension,
    inputs: &GradingInputs<'_>,
) -> QualityDimensionResult {
    let GradingInputs {
        binding,
        rule,
        applicability,
        evidence,
        rendered,
    } = *inputs;
    // The required set is the independent roster this dimension reads. It comes
    // from the protected floor's mandatory members, never from the evidence
    // list, so a duplicated handle cannot stand in for a member that was never
    // observed.
    let required = required_members(dimension, evidence);
    let observed: BTreeSet<ArtifactId> = rendered.iter().map(|atom| atom.atom_id.clone()).collect();
    let missing: Vec<ArtifactId> = required
        .iter()
        .filter(|id| !observed.contains(id))
        .cloned()
        .collect();
    let coverage = DimensionCoverage {
        required,
        observed,
        missing,
    };
    let dimension_applicability = applicability.for_dimension(dimension);
    let state = match &dimension_applicability {
        QualityApplicability::NotApplicable { reason } => QualityDimensionState::NotApplicable {
            reason: reason.clone(),
        },
        QualityApplicability::Unknown { unresolved } => {
            let limitation = unresolved.clone();
            return result(
                dimension,
                binding,
                rule,
                dimension_applicability,
                coverage,
                QualityDimensionState::Unknown,
                Some(limitation),
            );
        }
        QualityApplicability::Resolved => {
            if !coverage.missing.is_empty() || !unmet_evidence(dimension, evidence).is_empty() {
                QualityDimensionState::Unknown
            } else {
                QualityDimensionState::Passed
            }
        }
    };
    result(
        dimension,
        binding,
        rule,
        dimension_applicability,
        coverage,
        state,
        None,
    )
}

/// The member accounting one dimension was graded against.
struct DimensionCoverage {
    /// Members the protected floor independently required.
    required: Vec<ArtifactId>,
    /// Members actually present in the final rendered payload.
    observed: BTreeSet<ArtifactId>,
    /// Required members with no current observation.
    missing: Vec<ArtifactId>,
}

/// Exact members this dimension must account for.
fn required_members(
    dimension: QualityDimension,
    evidence: &QualityCompilationEvidence,
) -> Vec<ArtifactId> {
    let roles: &[SemanticRole] = match dimension {
        QualityDimension::RivalsConflictsUnknownsVisibility => &[SemanticRole::Conflict],
        QualityDimension::NegativeMemoryInvariantCoverage => &[SemanticRole::Negative],
        QualityDimension::InstructionSufficiency => &[SemanticRole::Instruction],
        QualityDimension::AcceptanceDecisionCoverage => &[SemanticRole::Acceptance],
        QualityDimension::VerifierActionReadiness => &[SemanticRole::Verifier],
        QualityDimension::ExactAnchorProvenanceCoverage => &[SemanticRole::Source],
        // A packet-wide dimension accounts for every member the floor required.
        _ => &[],
    };
    let members = evidence.required_roles.iter().filter(|role| {
        roles.is_empty() || roles.contains(&role.role)
    });
    members.flat_map(|role| role.required.iter().cloned()).collect()
}

/// Exact named evidence inputs this dimension consumes.
///
/// A role or a keyword is not evidence: decision and causal sufficiency require
/// the task/model/requirement owner's supported facts, provenance and freshness
/// require exact source evidence, and verifier readiness requires the
/// applicable current verifier/action contract rather than a zero-cost flag or
/// a past unrelated test pass.
fn unmet_evidence(
    dimension: QualityDimension,
    evidence: &QualityCompilationEvidence,
) -> Vec<&'static str> {
    let mut unmet = Vec::new();
    if matches!(
        dimension,
        QualityDimension::AcceptanceDecisionCoverage
            | QualityDimension::CausalOperationalSufficiency
    ) && evidence.supported_decision_facts.is_none()
    {
        unmet.push("supported_decision_facts");
    }
    if dimension == QualityDimension::VerifierActionReadiness && evidence.verifier_contract.is_none() {
        unmet.push("verifier_action_contract");
    }
    if dimension == QualityDimension::FreshnessStateFenceCoherence
        && evidence.evidence_revisions.is_empty()
    {
        unmet.push("evidence_revisions");
    }
    if dimension == QualityDimension::ExactAnchorProvenanceCoverage
        && evidence.coherent_read_evidence.is_none()
    {
        unmet.push("coherent_read_evidence");
    }
    unmet
}

/// Assemble the result record for one graded dimension.
fn result(
    dimension: QualityDimension,
    binding: &ContextBinding,
    rule: &QualityRuleRevision,
    applicability: QualityApplicability,
    coverage: DimensionCoverage,
    state: QualityDimensionState,
    limitation: Option<String>,
) -> QualityDimensionResult {
    let DimensionCoverage {
        required,
        observed,
        missing,
    } = coverage;
    // A pass claims the whole required member set as its observed evidence; any
    // other state keeps exactly the members it did observe.
    let evidence = if state.is_pass() {
        required.clone()
    } else {
        required
            .iter()
            .filter(|id| observed.contains(id))
            .cloned()
            .collect()
    };
    let limitation = limitation.or_else(|| {
        state.reason().map(str::to_owned).or_else(|| {
            (!missing.is_empty()).then(|| {
                format!(
                    "{} of {} required member(s) have no current observation",
                    missing.len(),
                    evidence.len() + missing.len()
                )
            })
        })
    });
    QualityDimensionResult {
        dimension,
        state,
        required_evidence: required,
        evidence,
        measurements: Vec::new(),
        missing_evidence: missing.clone(),
        stale_evidence: Vec::new(),
        failed_invariant: None,
        unknown_evidence: missing,
        applicability,
        rule: rule.clone(),
        limitation,
        // The builder grades from observed compilation evidence only, so every
        // result carries the observation ceiling the contracts crate already
        // uses for an explicitly incomplete compilation.
        proof_ceiling: ProofCeiling::Observation,
        invalidation: None,
        binding: binding.clone(),
    }
}
