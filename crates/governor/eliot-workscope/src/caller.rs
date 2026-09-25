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
    EvidenceStanding, GenerationEvidence, GuardTrigger, IdentityEvidence, PrivacyProfile,
    ProposalSource, RepositoryLineageIdentity, ResolutionAuthentication, ResourceExecutionIdentity,
    ScopeFingerprint, ScopeKind, ScopeLifecycle, SupportingEvidenceClass, WorkScopeBindingOwner,
    WorkScopeDescriptor, WorkScopeError, WorkScopeProposal, WorkScopeResolutionReceipt,
    WorkspaceInstanceIdentity, binding_matches_descriptor, counter, text, unique,
};
use eliot_bootstrap::capture::WorkspaceInstanceFacts;
use eliot_contracts::{
    ResourceGeneration, StateFence, canonical_json_bytes, fences_match_exact, sha256_hex,
};
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
        if let ResourceExecutionIdentity::InteractiveUser { sid_ref } = &self.execution_identity {
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

/// Admission decision bound to the trigger that requested it.
///
/// Records which mandatory point ran admission and what it decided. The
/// decision itself is a [`ReceiptAdmission`]: `Admitted` only, or the exact
/// [`WithholdReason`] otherwise. Withheld operations keep their reason so the
/// caller asks the cheapest discriminative question instead of retrying
/// against another candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriggerAdmission {
    pub trigger: GuardTrigger,
    pub scope_ref: String,
    pub decision: ReceiptAdmission,
}

impl TriggerAdmission {
    /// Validates the admission record without re-running admission.
    ///
    /// # Errors
    ///
    /// Returns an error when the bound scope reference is blank.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.scope_ref, "admission.scope_ref")
    }
}

/// Admits one trigger-gated operation against live owner authority.
///
/// This is the in-crate admission caller: it reads the live
/// [`WorkScopeBindingOwner`] at `fence` (fail-closed on a stale fence),
/// requires the retained binding to describe `descriptor`, requires the
/// receipt to select exactly that live binding on every identity field, and
/// only then runs [`verify_receipt_for_admission`] against the currently
/// observed generation evidence. Authority comes from the live owner read and
/// the retained descriptor — never from self-asserted receipt fields alone.
///
/// # Errors
///
/// Returns an error when the owner read, descriptor, receipt shape, or
/// generation evidence is malformed, or when live records disagree about
/// which scope is bound.
pub fn admit_at_trigger(
    owner: &WorkScopeBindingOwner,
    descriptor: &WorkScopeDescriptor,
    receipt: &WorkScopeResolutionReceipt,
    observed_generation: &GenerationEvidence,
    fence: &StateFence,
    trigger: GuardTrigger,
) -> Result<TriggerAdmission, WorkScopeError> {
    text(&receipt.receipt_ref, "receipt.receipt_ref")?;
    descriptor.validate()?;
    observed_generation.validate()?;
    let snapshot = owner
        .read_current(fence)
        .map_err(|_| WorkScopeError::StateFenceMismatch)?;
    let bound = &snapshot.binding.scope;
    if !binding_matches_descriptor(&snapshot.binding, descriptor) {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    let selected = &receipt.selected;
    if selected.scope_ref != bound.scope_ref
        || selected.kind != bound.kind
        || selected.lineage_ref != bound.lineage_ref
        || selected.instance_ref != bound.instance_ref
        || selected.root_identity != bound.root_identity
        || selected.generation != bound.generation
    {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    let decision = verify_receipt_for_admission(receipt, descriptor, observed_generation, fence)?;
    Ok(TriggerAdmission {
        trigger,
        scope_ref: bound.scope_ref.clone(),
        decision,
    })
}

/// Derives validated scope observations from mechanical workspace facts.
///
/// This is the identity-derivation policy for bootstrap observations: stable
/// locators (canonical root, worktree git dir, VCS common dir, root commit)
/// become identity, while branch, commit, dirty count, and task revision stay
/// generation/fence evidence and display/manifest/marker/remote values become
/// supporting evidence only. Identity digests are deterministic over the
/// observed locators, so the same worktree always derives the same instance
/// and lineage references and two worktrees never collide. The resource
/// generation is supplied by the caller from the current fence — it is never
/// read from clocks, proximity, or recency, which have no input here.
///
/// Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.
///
/// # Errors
///
/// Returns an error when the facts are mechanically invalid or the derived
/// observations fail validation.
pub fn derive_observed_resources(
    facts: &WorkspaceInstanceFacts,
    resource_generation: ResourceGeneration,
    display_name: Option<String>,
) -> Result<ObservedScopeResources, WorkScopeError> {
    facts
        .validate()
        .map_err(|_| WorkScopeError::InvalidSourceEvidence)?;
    let display_name = display_name
        .filter(|name| !name.trim().is_empty())
        .or_else(|| {
            std::path::Path::new(&facts.canonical_root)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| facts.canonical_root.clone());
    let instance_digest = sha256_hex(
        &canonical_json_bytes(&serde_json::json!({
            "toplevel": facts.canonical_root,
            "git_dir": facts.git_dir,
            "common_dir": facts.common_dir,
        }))
        .map_err(|_| WorkScopeError::InvalidSourceEvidence)?,
    );
    let lineage = match (&facts.common_dir, &facts.root_commit) {
        (Some(common_dir), Some(root_commit)) => {
            let lineage_digest = sha256_hex(
                &canonical_json_bytes(&serde_json::json!({
                    "common_dir": common_dir,
                    "root_commit": root_commit,
                }))
                .map_err(|_| WorkScopeError::InvalidSourceEvidence)?,
            );
            Some(RepositoryLineageIdentity {
                lineage_ref: format!("lineage-{lineage_digest}"),
                object_store_ref: common_dir.clone(),
                initial_history_ref: root_commit.clone(),
                normalized_remote_ref: facts.remote_url.clone(),
                manifest_identity_ref: None,
            })
        }
        _ => None,
    };
    let instance = WorkspaceInstanceIdentity {
        instance_ref: format!("ws-{instance_digest}"),
        root_identity: facts.canonical_root.clone(),
        vcs_identity_ref: facts.git_dir.clone(),
        generation: resource_generation.value(),
    };
    let dirty_summary_ref = (facts.dirty_files > 0).then(|| format!("dirty:{}", facts.dirty_files));
    let generation = GenerationEvidence {
        branch_ref: facts.head_branch.clone(),
        commit_ref: facts.head_commit.clone(),
        dirty_summary_ref,
        task_revision: None,
        resource_generation,
    };
    let mut supporting_evidence = vec![IdentityEvidence {
        class: SupportingEvidenceClass::DisplayName,
        detail_ref: display_name.clone(),
        standing: EvidenceStanding::Supporting,
    }];
    for manifest in &facts.manifest_names {
        supporting_evidence.push(IdentityEvidence {
            class: SupportingEvidenceClass::ManifestNameMatch,
            detail_ref: manifest.clone(),
            standing: EvidenceStanding::Supporting,
        });
    }
    if let Some(remote) = &facts.remote_url {
        supporting_evidence.push(IdentityEvidence {
            class: SupportingEvidenceClass::RemoteUrl,
            detail_ref: remote.clone(),
            standing: EvidenceStanding::Supporting,
        });
    }
    if facts.eliot_marker_present {
        supporting_evidence.push(IdentityEvidence {
            class: SupportingEvidenceClass::CopiedMarker,
            detail_ref: ".eliot".to_owned(),
            standing: EvidenceStanding::Supporting,
        });
    }
    let observed = ObservedScopeResources {
        kind: if facts.has_git {
            ScopeKind::GitRepo
        } else {
            ScopeKind::Directory
        },
        display_name,
        lineage,
        instances: vec![instance],
        canonical_resource_refs: Vec::new(),
        external_resource_refs: Vec::new(),
        root_identities: vec![facts.canonical_root.clone()],
        generation,
        supporting_evidence,
    };
    observed.validate()?;
    Ok(observed)
}
