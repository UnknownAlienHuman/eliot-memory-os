//! Production caller seam for `WorkScope` identity (issue #1787, caller slice).
//!
//! This module answers, in the owner crate, three caller questions without
//! building the later engine slices:
//!
//! - who constructs a [`WorkScopeDescriptor`] from live resources: the
//!   bootstrap-scanner/attach caller supplies [`ObservedScopeResources`] read
//!   from real VCS, filesystem, and process observations, then calls
//!   [`describe_observed_scope`];
//! - who requests resolution: the same caller packages [`propose_scope`] with
//!   authenticated identities kept separate from hint evidence; resolver
//!   ordering (I4.2) stays a follow-up that consumes the proposal;
//! - who consumes a [`WorkScopeResolutionReceipt`] plus [`GenerationEvidence`]
//!   at admission: [`verify_receipt_for_admission`] re-checks identity,
//!   fingerprint, generation, and fence, returning [`ReceiptAdmission`] instead
//!   of a boolean so a withheld operation keeps its exact reason.
//!
//! Fail-closed construction rules, enforced here so callers cannot launder
//! aliases into identity:
//!
//! - lineage evidence is never invented: a `GitRepo` descriptor requires an
//!   observed [`RepositoryLineageIdentity`]; observations without lineage
//!   evidence stay provisional and unauthenticated;
//! - branch, commit, dirty state, and task revision travel only inside
//!   [`GenerationEvidence`] and never enter [`ScopeFingerprint`];
//! - display names, proximity, recency, manifest names, copied markers, and
//!   remote URLs travel only inside [`IdentityEvidence`].
//!
//! Guard trigger points (I4.2.1), resolver ordering (I4.2), admission wiring,
//! and attach reconciliation remain follow-up/owner slices; they consume these
//! seams rather than re-implementing them.

use super::{
    GenerationEvidence, IdentityEvidence, PrivacyProfile, ProposalSource,
    RepositoryLineageIdentity, ResolutionAuthentication, ResourceExecutionIdentity, ScopeFingerprint,
    ScopeKind, ScopeLifecycle, WorkScopeDescriptor, WorkScopeError, WorkScopeProposal,
    WorkScopeResolutionReceipt, WorkspaceInstanceIdentity, counter, text, unique,
};
use eliot_contracts::{StateFence, fences_match_exact};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Live scope observation supplied by the scanner/attach caller.
///
/// Every identity-bearing field must come from a real resource read (VCS
/// common-dir/object-store identity, filesystem identity, observed process or
/// editor binding). Blank or duplicated references fail validation; missing
/// lineage evidence forces the provisional path instead of an invented lineage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservedScopeResources {
    pub kind: ScopeKind,
    pub display_name: String,
    pub lineage: Option<RepositoryLineageIdentity>,
    pub instances: Vec<WorkspaceInstanceIdentity>,
    pub canonical_resource_refs: Vec<String>,
    pub external_resource_refs: Vec<String>,
    pub root_identities: Vec<String>,
    pub generation: GenerationEvidence,
    pub supporting_evidence: Vec<IdentityEvidence>,
}

/// Non-resource policy metadata the owning caller binds to a descriptor.
///
/// Owners, privacy, authority, execution identity, and capabilities are policy
/// decisions, not resource observations; they ride with the descriptor but
/// never enter the identity fingerprint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptorPolicy {
    pub owner_refs: Vec<String>,
    pub truth_surface_refs: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub privacy: PrivacyProfile,
    pub authority_profile_ref: Option<String>,
    pub execution_identity: ResourceExecutionIdentity,
    pub available_capabilities: Vec<String>,
    pub missing_capabilities: Vec<String>,
}

/// Why admission on a resolution receipt is withheld.
///
/// A withheld operation keeps its exact reason so the caller can ask the
/// cheapest discriminative question or trigger revalidation; nothing is
/// silently retried against a different candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WithholdReason {
    ProvisionalAuthentication,
    FingerprintMismatch,
    IdentityMismatch,
    GenerationMismatch,
    FenceMismatch,
}

/// Admission decision for one resolution receipt at one fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptAdmission {
    Admitted,
    Withheld(WithholdReason),
}

fn text_collection(values: &[String], field: &'static str) -> Result<(), WorkScopeError> {
    for value in values {
        text(value, field)?;
    }
    unique(values.iter(), field)
}

impl ObservedScopeResources {
    /// Validates live observations without authenticating any binding.
    ///
    /// # Errors
    ///
    /// Returns an error when the display name is blank, no exact workspace
    /// instance was observed, instance or lineage evidence is invalid or
    /// duplicated, a resource reference is blank or duplicated, generation
    /// evidence is malformed, or supporting evidence is blank.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.display_name, "observed.display_name")?;
        if let Some(lineage) = &self.lineage {
            lineage.validate()?;
        }
        if self.instances.is_empty() {
            return Err(WorkScopeError::EmptyCollection {
                field: "observed.instances",
            });
        }
        for instance in &self.instances {
            instance.validate()?;
        }
        unique(
            self.instances.iter().map(|instance| &instance.instance_ref),
            "observed.instances",
        )?;
        text_collection(
            &self.canonical_resource_refs,
            "observed.canonical_resource_refs",
        )?;
        text_collection(
            &self.external_resource_refs,
            "observed.external_resource_refs",
        )?;
        text_collection(&self.root_identities, "observed.root_identities")?;
        self.generation.validate()?;
        for item in &self.supporting_evidence {
            text(&item.detail_ref, "observed.evidence.detail_ref")?;
        }
        Ok(())
    }
}

impl DescriptorPolicy {
    /// Validates caller-supplied policy metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when a reference is blank or duplicated, one
    /// capability is both available and missing, privacy evidence is invalid,
    /// or the authority/execution references are blank.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text_collection(&self.owner_refs, "policy.owner_refs")?;
        text_collection(&self.truth_surface_refs, "policy.truth_surface_refs")?;
        text_collection(&self.verifier_refs, "policy.verifier_refs")?;
        text_collection(
            &self.available_capabilities,
            "policy.available_capabilities",
        )?;
        text_collection(&self.missing_capabilities, "policy.missing_capabilities")?;
        if self
            .available_capabilities
            .iter()
            .any(|capability| self.missing_capabilities.contains(capability))
        {
            return Err(WorkScopeError::DuplicateReference {
                field: "policy.available_and_missing_capabilities",
            });
        }
        self.privacy.validate()?;
        if let Some(authority) = &self.authority_profile_ref {
            text(authority, "policy.authority_profile_ref")?;
        }
        if let ResourceExecutionIdentity::InteractiveUser { sid_ref } = &self.execution_identity
        {
            text(sid_ref, "policy.execution_identity.sid_ref")?;
        }
        Ok(())
    }
}

/// Builds a validated descriptor from live observations plus caller policy.
///
/// This is the scanner/attach-path constructor: `observed` carries what was
/// actually read, `policy` carries what the owner asserts, and `fence` carries
/// the current Kernel fence. A `GitRepo` descriptor without observed lineage
/// evidence is rejected instead of receiving an invented lineage; such
/// observations must stay provisional until lineage evidence exists.
///
/// # Errors
///
/// Returns an error when observations or policy are invalid, the scope
/// reference is blank, the descriptor revision is zero, a repository scope
/// has no lineage evidence, or the state fence is invalid.
pub fn describe_observed_scope(
    scope_ref: impl Into<String>,
    descriptor_revision: u64,
    lifecycle: ScopeLifecycle,
    observed: &ObservedScopeResources,
    policy: &DescriptorPolicy,
    fence: &StateFence,
) -> Result<WorkScopeDescriptor, WorkScopeError> {
    let scope_ref = scope_ref.into();
    text(&scope_ref, "scope_ref")?;
    counter(descriptor_revision, "descriptor_revision")?;
    observed.validate()?;
    policy.validate()?;
    if observed.kind == ScopeKind::GitRepo && observed.lineage.is_none() {
        return Err(WorkScopeError::EmptyCollection {
            field: "observed.lineage",
        });
    }
    fence
        .validate()
        .map_err(|_| WorkScopeError::InvalidStateFence)?;
    let descriptor = WorkScopeDescriptor {
        scope_ref,
        descriptor_revision,
        kind: observed.kind,
        display_name: observed.display_name.clone(),
        lineage: observed.lineage.clone(),
        instances: observed.instances.clone(),
        owner_refs: policy.owner_refs.clone(),
        canonical_resource_refs: observed.canonical_resource_refs.clone(),
        root_identities: observed.root_identities.clone(),
        external_resource_refs: observed.external_resource_refs.clone(),
        truth_surface_refs: policy.truth_surface_refs.clone(),
        verifier_refs: policy.verifier_refs.clone(),
        privacy: policy.privacy.clone(),
        authority_profile_ref: policy.authority_profile_ref.clone(),
        execution_identity: policy.execution_identity.clone(),
        generation: observed.generation.clone(),
        state_fence: fence.clone(),
        available_capabilities: policy.available_capabilities.clone(),
        missing_capabilities: policy.missing_capabilities.clone(),
        lifecycle,
    };
    descriptor.validate()?;
    Ok(descriptor)
}

/// Packages a resolution request from live observations.
///
/// Authenticated root/resource identities stay in `authenticated_identities`;
/// paths, names, and hints stay in the observation's supporting evidence.
/// Resolver ordering consumes this proposal; it does not run here.
///
/// # Errors
///
/// Returns an error when proposal references are blank, observations are
/// invalid, an authenticated identity or competing reference is blank or
/// duplicated, or requested privacy/authority references are invalid.
#[allow(clippy::too_many_arguments)]
pub fn propose_scope(
    proposal_ref: impl Into<String>,
    proposer_ref: impl Into<String>,
    source: ProposalSource,
    observed: &ObservedScopeResources,
    authenticated_identities: Vec<String>,
    competing_candidate_refs: Vec<String>,
    requested_privacy: Option<PrivacyProfile>,
    requested_authority_profile_ref: Option<String>,
) -> Result<WorkScopeProposal, WorkScopeError> {
    let proposal = WorkScopeProposal {
        proposal_ref: proposal_ref.into(),
        proposer_ref: proposer_ref.into(),
        proposed_kind: observed.kind,
        proposed_lineage: observed.lineage.clone(),
        proposed_instances: observed.instances.clone(),
        source,
        authenticated_identities,
        supporting_evidence: observed.supporting_evidence.clone(),
        competing_candidate_refs,
        requested_privacy,
        requested_authority_profile_ref,
    };
    proposal.validate()?;
    Ok(proposal)
}

/// Verifies one resolution receipt against the retained descriptor at admission.
///
/// Consumes the receipt plus currently observed [`GenerationEvidence`] and the
/// admission fence, in order: authentication level, fingerprint equality
/// against the descriptor's stable resources, selected-identity membership
/// (scope, kind, lineage, exact instance and root — never alias equality
/// alone), generation agreement with what is observed right now, and exact
/// fence match. Anything else withholds with its exact reason; malformed
/// inputs fail as errors rather than as admissions.
///
/// This is the admission seam, not the guard engine: trigger points,
/// revalidation policy, and rebind/relocation authorization live in
/// follow-up slices.
///
/// # Errors
///
/// Returns an error when the receipt, descriptor, or observed generation is
/// malformed.
pub fn verify_receipt_for_admission(
    receipt: &WorkScopeResolutionReceipt,
    descriptor: &WorkScopeDescriptor,
    observed_generation: &GenerationEvidence,
    fence: &StateFence,
) -> Result<ReceiptAdmission, WorkScopeError> {
    receipt.validate()?;
    descriptor.validate()?;
    observed_generation.validate()?;
    if receipt.authentication != ResolutionAuthentication::Authenticated {
        return Ok(ReceiptAdmission::Withheld(
            WithholdReason::ProvisionalAuthentication,
        ));
    }
    if receipt.fingerprint != ScopeFingerprint::derive_for(descriptor) {
        return Ok(ReceiptAdmission::Withheld(
            WithholdReason::FingerprintMismatch,
        ));
    }
    let selected = &receipt.selected;
    let lineage_matches = selected.lineage_ref
        == descriptor
            .lineage
            .as_ref()
            .map(|lineage| lineage.lineage_ref.clone());
    let instance_matches = descriptor.instances.iter().any(|instance| {
        instance.instance_ref == selected.instance_ref
            && instance.root_identity == selected.root_identity
    });
    if selected.scope_ref != descriptor.scope_ref
        || selected.kind != descriptor.kind
        || !lineage_matches
        || !instance_matches
    {
        return Ok(ReceiptAdmission::Withheld(WithholdReason::IdentityMismatch));
    }
    if selected.generation != observed_generation.resource_generation.value() {
        return Ok(ReceiptAdmission::Withheld(
            WithholdReason::GenerationMismatch,
        ));
    }
    if !fences_match_exact(&receipt.state_fence, fence) {
        return Ok(ReceiptAdmission::Withheld(WithholdReason::FenceMismatch));
    }
    Ok(ReceiptAdmission::Admitted)
}
