//! Runner binding from executable capsule revisions to admitted profiles.
//!
//! This module is the InstrumentRunner/resolver join for issue #1804: it binds
//! one [`ExecutableModuleTestCapsuleRevision`](eliot_contracts::ExecutableModuleTestCapsuleRevision)
//! plus its [`BoundCapsuleSelection`](eliot_contracts::BoundCapsuleSelection)
//! to an exact admitted profile revision, producing a typed
//! [`BoundCapsulePlan`] the composition root launches through the existing
//! runner primitives. It owns no discovery (#1802), no impact selection
//! (#1803), and no registry (#13); it only joins their validated outputs.
//!
//! Binding rules, all fail-closed:
//!
//! * The capsule descriptor must validate, and the selection must have been
//!   resolved for this exact capsule: swapped selections are rejected.
//! * The registry binding must be executable (`PRODUCTION` or
//!   `EXTERNALLY_SCHEDULED`) and its digest must equal the capsule digest;
//!   stale bindings are rejected, never rebound.
//! * The profile resolves at its exact revision through
//!   [`ProfileCompiler::compile_exact`]: unknown profiles or revisions are
//!   unavailable, never silently promoted or quarantined into a claim.
//! * Independence is re-checked at bind time: a class that forbids services
//!   with any declared service fails binding, so a pure capsule can never
//!   plan unrelated production services. Service capsules carry only their
//!   declared owned fixtures; Cargo compilation dependencies stay allowed.
//! * Attribution is structural: the plan and the assembled evidence name the
//!   exact cell plus the selected tests, never all cells sharing a package.
//! * Proof ceilings bound claims: fake-port tests keep the capsule's declared
//!   ceiling, and naming a production trait never raises it. Only a new
//!   capsule revision with a higher declared ceiling changes the answer.
//!
//! The binding synthesizes no commands: [`nextest_test_filters`] projects
//! typed test identities from the selection for the existing nextest adapter,
//! whose [`NextestCommand`](eliot_instrument_nextest::NextestCommand) still
//! validates and matches the sealed process request. Package/binary scoping
//! beyond test-id filters stays with the nextest adapter owner.

use eliot_contracts::{
    BoundCapsuleSelection, CapsuleExecutionEvidence, CapsuleResourceRef, CapsuleSerialGroupRef,
    CapsuleServiceRef, CapsuleStage, CapsuleTargetSpec, CellCapsuleBinding, CleanupOutcome,
    CleanupPolicy, ContractDigest, EvidenceCapture, ExecutableModuleTestCapsuleRevision,
    ExecutedTest, ExecutionOutcome, ExpectedDiscovery, FixtureBinding, ModuleTestCapsuleError,
    ObservedAdmission, OmittedTest, OracleBinding, OracleReviewRef, ProofCeiling, RawArtifact,
    SelectedTest, StageOutcome, TypedTestSelector, sha256_hex,
};
use thiserror::Error;

use crate::profile::{
    AdmittedProfile, AdmittedStage, InstrumentRegistry, ProfileCompiler, ProfileError,
};

/// Failures raised while binding a capsule to an admitted profile.
#[derive(Debug, Error)]
pub enum CapsuleBindingError {
    /// The capsule descriptor, binding, or evidence failed validation.
    #[error(transparent)]
    Capsule(#[from] ModuleTestCapsuleError),
    /// The capsule is unavailable; see the typed cause.
    #[error(transparent)]
    Unavailable(#[from] eliot_contracts::CapsuleUnavailable),
    /// Profile admission failed: unknown profile or revision.
    #[error(transparent)]
    Profile(#[from] ProfileError),
    /// A required text value is blank or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Field that failed validation.
        field: &'static str,
    },
    /// The registry binding disposition is not executable. Only production
    /// and externally scheduled bindings dispatch.
    #[error("cell '{cell}' disposition '{disposition}' is not executable")]
    NonExecutableDisposition {
        /// Cell with the non-executable binding.
        cell: String,
        /// Disposition that refused dispatch.
        disposition: String,
    },
    /// The selection was not resolved for this exact capsule.
    #[error("capsule '{capsule}' selection mismatch: {detail}")]
    SelectionMismatch {
        /// Capsule with the mismatched selection.
        capsule: String,
        /// How the selection diverges.
        detail: String,
    },
    /// The registry binding digest does not match the capsule revision.
    #[error("cell '{cell}' binding is stale: expected '{expected}', found '{found}'")]
    BindingDigestMismatch {
        /// Cell with the stale binding.
        cell: String,
        /// Digest carried by the registry binding.
        expected: String,
        /// Digest of the capsule revision.
        found: String,
    },
    /// The capsule would start services its class forbids.
    #[error("capsule '{capsule}' independence violation: {detail}")]
    IndependenceViolation {
        /// Capsule violating independence.
        capsule: String,
        /// What the capsule would wrongly start.
        detail: String,
    },
}

/// Bound executable plan for one capsule revision through one admitted profile.
///
/// Every field is admission-sealed or resolution-bound: the exact cell,
/// capsule digest, profile revision plus definition digests, typed selector,
/// target, declared services/resources/policy, expected rule, ceiling, and
/// the selected/omitted sets with the inventory digest behind them. The
/// composition root launches each admitted stage through the existing
/// [`StageLauncher`](crate::StageLauncher) path; this plan invents no
/// invocation, request, or sink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundCapsulePlan {
    /// Cell under proof.
    pub cell: String,
    /// Capsule identity.
    pub capsule: String,
    /// Digest of the exact capsule revision bound.
    pub capsule_digest: String,
    /// Candidate the plan is bound to.
    pub candidate: String,
    /// Admitted profile name.
    pub profile: String,
    /// Exact admitted profile revision.
    pub profile_revision: u64,
    /// Admitted profile definition digest.
    pub profile_digest: String,
    /// Admitted stage DAG digest.
    pub dag_digest: String,
    /// Admitted stages in deterministic topological order.
    pub stages: Vec<AdmittedStage>,
    /// Typed package/binary/test selector.
    pub selector: TypedTestSelector,
    /// Compilation target and required features.
    pub target: CapsuleTargetSpec,
    /// Declared stage classes, kept distinct for evidence attribution.
    pub declared_stages: Vec<CapsuleStage>,
    /// Owned fixture services the run may start. Empty unless the capsule
    /// class allows services.
    pub services: Vec<CapsuleServiceRef>,
    /// Declared resource classes.
    pub resources: Vec<CapsuleResourceRef>,
    /// Serial group, when serialization applies.
    pub serial_group: Option<CapsuleSerialGroupRef>,
    /// Execution timeout in seconds.
    pub timeout_secs: u64,
    /// Cleanup policy for execution roots.
    pub cleanup: CleanupPolicy,
    /// Expected discovery rule enforced on the retained evidence.
    pub expected: ExpectedDiscovery,
    /// Highest proof level this plan may claim.
    pub proof_ceiling: ProofCeiling,
    /// Whether this plan covers static compilation only.
    pub compile_only: bool,
    /// Selected tests, attributed to the exact cell.
    pub selected: Vec<SelectedTest>,
    /// Omitted discovered tests with reasons.
    pub omitted: Vec<OmittedTest>,
    /// Digest of the inventory snapshot behind the selection.
    pub inventory_digest: String,
    /// Resolution digest over registry, capsule, selection, and candidate.
    pub resolution_digest: String,
}

/// Binds one resolved capsule to its exact admitted profile revision.
///
/// The registry binding gates dispatch: only executable dispositions with a
/// current digest proceed. See the module documentation for the full rule set.
///
/// # Errors
///
/// Returns [`CapsuleBindingError`] when the descriptor, binding, selection
/// join, profile admission, candidate, or independence check fails.
pub fn bind_capsule(
    registry: &InstrumentRegistry,
    capsule: &ExecutableModuleTestCapsuleRevision,
    selection: &BoundCapsuleSelection,
    binding: &CellCapsuleBinding,
    candidate: &str,
) -> Result<BoundCapsulePlan, CapsuleBindingError> {
    capsule.validate()?;
    check_candidate(candidate)?;
    check_binding(capsule, binding)?;
    check_selection(capsule, selection)?;
    check_independence(capsule)?;
    let admitted = ProfileCompiler::new(registry)
        .compile_exact(capsule.profile.as_str(), capsule.profile_revision)?;
    Ok(assemble_plan(
        registry, capsule, selection, &admitted, candidate,
    ))
}

fn check_candidate(candidate: &str) -> Result<(), CapsuleBindingError> {
    if candidate.trim().is_empty() || candidate.chars().any(char::is_control) {
        return Err(CapsuleBindingError::InvalidText { field: "candidate" });
    }
    Ok(())
}

fn check_binding(
    capsule: &ExecutableModuleTestCapsuleRevision,
    binding: &CellCapsuleBinding,
) -> Result<(), CapsuleBindingError> {
    let cell = capsule.cell.as_str();
    binding.validate(cell)?;
    if !binding.disposition.is_executable() {
        return Err(CapsuleBindingError::NonExecutableDisposition {
            cell: cell.to_owned(),
            disposition: format!("{:?}", binding.disposition),
        });
    }
    let digest = capsule.capsule_digest()?;
    let bound = binding
        .capsule_digest
        .as_ref()
        .map_or("", |value| value.as_str());
    if bound != digest {
        return Err(CapsuleBindingError::BindingDigestMismatch {
            cell: cell.to_owned(),
            expected: bound.to_owned(),
            found: digest,
        });
    }
    Ok(())
}

fn check_selection(
    capsule: &ExecutableModuleTestCapsuleRevision,
    selection: &BoundCapsuleSelection,
) -> Result<(), CapsuleBindingError> {
    let name = capsule.capsule.as_str().to_owned();
    if selection.capsule != capsule.capsule
        || selection.cell != capsule.cell
        || selection.profile != capsule.profile
        || selection.profile_revision != capsule.profile_revision
    {
        return Err(CapsuleBindingError::SelectionMismatch {
            capsule: name,
            detail: "selection identity, cell, or profile does not match the capsule".to_owned(),
        });
    }
    let digest = capsule.capsule_digest()?;
    if selection.capsule_digest.as_str() != digest {
        return Err(CapsuleBindingError::SelectionMismatch {
            capsule: name,
            detail: "selection capsule digest does not match the capsule revision".to_owned(),
        });
    }
    Ok(())
}

fn check_independence(
    capsule: &ExecutableModuleTestCapsuleRevision,
) -> Result<(), CapsuleBindingError> {
    if capsule.proof_class.minimum_proof().allows_services {
        return Ok(());
    }
    if let Some(service) = capsule.services.services.first() {
        return Err(CapsuleBindingError::IndependenceViolation {
            capsule: capsule.capsule.as_str().to_owned(),
            detail: format!(
                "class forbids services but the plan would start '{}'",
                service.as_str(),
            ),
        });
    }
    Ok(())
}

fn assemble_plan(
    registry: &InstrumentRegistry,
    capsule: &ExecutableModuleTestCapsuleRevision,
    selection: &BoundCapsuleSelection,
    admitted: &AdmittedProfile,
    candidate: &str,
) -> BoundCapsulePlan {
    let mut selected_material = String::new();
    for entry in &selection.selected {
        selected_material.push_str(entry.package.as_str());
        selected_material.push('\0');
        selected_material.push_str(entry.binary.as_str());
        selected_material.push('\0');
        selected_material.push_str(entry.test.as_str());
        selected_material.push('\0');
    }
    let capsule_digest = selection.capsule_digest.as_str();
    let resolution_digest = sha256_hex(
        format!(
            "{}\0{}\0{capsule_digest}\0{}\0{}\0{}\0{selected_material}",
            registry.generation(),
            registry.digest(),
            admitted.profile_digest,
            admitted.dag_digest,
            selection.inventory_digest.as_str(),
        )
        .as_bytes(),
    );
    BoundCapsulePlan {
        cell: capsule.cell.as_str().to_owned(),
        capsule: capsule.capsule.as_str().to_owned(),
        capsule_digest: capsule_digest.to_owned(),
        candidate: candidate.to_owned(),
        profile: admitted.name.clone(),
        profile_revision: admitted.revision,
        profile_digest: admitted.profile_digest.clone(),
        dag_digest: admitted.dag_digest.clone(),
        stages: admitted.stages.clone(),
        selector: capsule.selector.clone(),
        target: capsule.target.clone(),
        declared_stages: capsule.stages.clone(),
        services: capsule.services.services.clone(),
        resources: capsule.services.resources.clone(),
        serial_group: capsule.services.policy.serial_group.clone(),
        timeout_secs: capsule.services.policy.timeout_secs,
        cleanup: capsule.services.policy.cleanup.clone(),
        expected: capsule.expected_discovery,
        proof_ceiling: capsule.proof_ceiling,
        compile_only: selection.compile_only,
        selected: selection.selected.clone(),
        omitted: selection.omitted.clone(),
        inventory_digest: selection.inventory_digest.as_str().to_owned(),
        resolution_digest,
    }
}

/// Projects typed test identities from a bound plan for the nextest adapter.
///
/// Each filter is one exact selected test identity from resolution; nothing
/// is invented, and no command string passes through here. The nextest
/// adapter still validates the invocation and matches the sealed process
/// request before anything launches.
pub fn nextest_test_filters(plan: &BoundCapsulePlan) -> Vec<String> {
    let mut filters: Vec<String> = plan
        .selected
        .iter()
        .map(|entry| entry.test.as_str().to_owned())
        .collect();
    filters.sort();
    filters.dedup();
    filters
}

/// Whether `ceiling` admits an edge-level proof claim.
///
/// A `MODULE_EDGE_PROOF` ceiling admits module and edge claims; a
/// `PRODUCT_PROOF` ceiling admits those plus product claims. Fake-port tests
/// keep the capsule's declared ceiling: they can never become edge proof by
/// naming the production trait.
pub fn ceiling_admits_edge_claim(ceiling: ProofCeiling) -> bool {
    matches!(
        ceiling,
        ProofCeiling::ModuleEdgeProof | ProofCeiling::ProductProof
    )
}

/// Whether `ceiling` admits a product-level proof claim.
///
/// Only a `PRODUCT_PROOF` ceiling admits product claims. No name, trait
/// reference, or test title raises the ceiling; only a new capsule revision
/// with a higher declared ceiling, re-resolved and re-bound, does.
pub fn ceiling_admits_product_claim(ceiling: ProofCeiling) -> bool {
    matches!(ceiling, ProofCeiling::ProductProof)
}

/// Terminal observations the composition root supplies for evidence assembly.
///
/// Every field is machine-observed or Governor-observed evidence from the
/// actual run: discovered and executed identities, per-stage outcomes, raw
/// artifacts, outcome, capture, admission, cleanup, and the fixture/oracle
/// bindings the run really used. The assembler checks them against the plan
/// and the capsule revision instead of trusting them.
#[derive(Clone, Debug)]
pub struct CapsuleRunObservation {
    /// Tests the run discovered.
    pub discovered: Vec<SelectedTest>,
    /// Tests the run executed, with outcomes.
    pub executed: Vec<ExecutedTest>,
    /// Per-stage outcomes, one per declared stage class.
    pub stages: Vec<StageOutcome>,
    /// Retained raw artifacts.
    pub raw_artifacts: Vec<RawArtifact>,
    /// Terminal outcome of the run.
    pub outcome: ExecutionOutcome,
    /// Raw-output capture state.
    pub capture: EvidenceCapture,
    /// Observed Governor admission state.
    pub admission: ObservedAdmission,
    /// Cleanup outcome for execution roots.
    pub cleanup: CleanupOutcome,
    /// Fixture binding the run really used.
    pub fixture: FixtureBinding,
    /// Oracle binding the run really used.
    pub oracle: OracleBinding,
    /// Separate oracle review, required when the oracle changed.
    pub oracle_review: Option<OracleReviewRef>,
    /// Digest of the retained evidence this run replays, when replaying.
    pub replay_of: Option<ContractDigest>,
}

/// Assembles retained execution evidence from a bound plan plus terminal
/// observations (step 7 surface in the runner).
///
/// The evidence reuses the neutral [`CapsuleExecutionEvidence`](eliot_contracts::CapsuleExecutionEvidence)
/// type: this module defines no second evidence vocabulary. Assembly checks
/// the observations against the plan and the capsule revision, so a stale or
/// unmatched selector cannot silently pass, expected-nonzero with zero
/// execution cannot pass, and an oracle change without the separate review
/// cannot pass.
///
/// # Errors
///
/// Returns [`CapsuleBindingError::Capsule`] when the assembled evidence is
/// internally inconsistent or diverges from the capsule revision.
pub fn assemble_evidence(
    plan: &BoundCapsulePlan,
    capsule: &ExecutableModuleTestCapsuleRevision,
    observation: CapsuleRunObservation,
) -> Result<CapsuleExecutionEvidence, CapsuleBindingError> {
    let capsule_digest = ContractDigest::new(plan.capsule_digest.clone())
        .map_err(ModuleTestCapsuleError::Contract)?;
    let candidate = eliot_contracts::CapsuleCandidateRef::new(plan.candidate.clone())
        .map_err(ModuleTestCapsuleError::Contract)?;
    let evidence = CapsuleExecutionEvidence {
        capsule: capsule.capsule.clone(),
        capsule_digest,
        cell: capsule.cell.clone(),
        profile: capsule.profile.clone(),
        profile_revision: capsule.profile_revision,
        candidate,
        expected: plan.expected,
        discovered: observation.discovered,
        selected: plan.selected.clone(),
        executed: observation.executed,
        omitted: plan.omitted.clone(),
        fixture: observation.fixture,
        oracle: observation.oracle,
        oracle_review: observation.oracle_review,
        resources: plan.resources.clone(),
        raw_artifacts: observation.raw_artifacts,
        outcome: observation.outcome,
        capture: observation.capture,
        admission: observation.admission,
        stages: observation.stages,
        cleanup: observation.cleanup,
        replay_of: observation.replay_of,
    };
    evidence.validate()?;
    evidence.validate_against(capsule)?;
    Ok(evidence)
}
