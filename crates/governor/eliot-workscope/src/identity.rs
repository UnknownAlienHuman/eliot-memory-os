//! Durable `WorkScope` identity representations (issue #1787, slice 1).
//!
//! This module owns the identity half of I4.1/I4.3.1: the versioned
//! [`WorkScopeDescriptor`], the [`WorkScopeProposal`] /
//! [`WorkScopeResolutionReceipt`] pair, and the [`ScopeRelocationOrAttachReceipt`]
//! that records an authorized move, additional clone, or attach without rewriting
//! the old root identity or task history.
//!
//! Three evidence classes stay strictly separated:
//!
//! - **Stable resource identity** ([`RepositoryLineageIdentity`],
//!   [`WorkspaceInstanceIdentity`], canonical/external resource references) is the
//!   only input to [`ScopeFingerprint`].
//! - **Generation/fence evidence** ([`GenerationEvidence`]: branch, commit, dirty
//!   summary, task revision, resource generation) is carried alongside identity but
//!   never defines it; a generation change requires fresh guard revalidation, not a
//!   new scope.
//! - **Supporting evidence** ([`IdentityEvidence`]: display names, directory
//!   proximity, recency, manifest-name matches, copied `.eliot` markers, remote
//!   URLs) can discriminate candidates but can never authenticate a scope.
//!
//! Resolver ordering (I4.2) and `ScopeBindingGuard` triggers (I4.2.1) are later
//! slices. These types carry the fields that ordering and guards consume
//! (authenticated identities, competing candidates, per-candidate evidence,
//! selected scope/generation, authority, state fence) without implementing the
//! ordering or the trigger checks themselves.

use super::{
    PrivacyProfile, RepositoryLineageIdentity, ScopeIdentity, ScopeKind, WorkScopeError,
    WorkspaceInstanceIdentity, counter, text, unique,
};
use eliot_contracts::{ResourceGeneration, StateFence, TaskRevision};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Lifecycle state carried by a versioned [`WorkScopeDescriptor`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeLifecycle {
    Provisional,
    Active,
    Suspended,
    Archived,
}

/// Required execution identity for the scope's resources.
///
/// This records which principal class must back the scope's effects; it carries
/// no credential material and grants no authority by itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceExecutionIdentity {
    Service,
    InteractiveUser { sid_ref: String },
    Remote,
}

/// Generation/fence evidence: branch, commit, dirty state, and task revision.
///
/// These values ride with a scope observation so guards can detect change, but
/// they are never scope identity: two observations with different branches or
/// commits may still name the same scope, and equal branches or commits never
/// prove two checkouts are the same workspace instance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenerationEvidence {
    pub branch_ref: Option<String>,
    pub commit_ref: Option<String>,
    pub dirty_summary_ref: Option<String>,
    pub task_revision: Option<TaskRevision>,
    pub resource_generation: ResourceGeneration,
}

/// Deterministic fingerprint derived only from stable resource identities.
///
/// The derivation consumes the scope reference, kind, lineage evidence,
/// workspace-instance evidence, and canonical/external resource references. It
/// never consumes the display name, generation evidence, supporting evidence,
/// descriptor revision, lifecycle, privacy, authority, capabilities, or fence:
/// none of those may merge, split, or rename a scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeFingerprint {
    pub value: String,
}

/// Evidence class that may discriminate candidates but never authenticate scope.
///
/// Display names, directory proximity, recency, matching manifest names, copied
/// `.eliot` markers, and remote URLs are supporting evidence only; a copied
/// marker cannot grant scope authority and a near path cannot select a scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportingEvidenceClass {
    DisplayName,
    DirectoryProximity,
    Recency,
    ManifestNameMatch,
    CopiedMarker,
    RemoteUrl,
}

/// Whether one evidence item supports, contradicts, or is missing for a candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStanding {
    Supporting,
    Conflicting,
    Missing,
}

/// One supporting/conflicting/missing evidence item bound to a candidate.
///
/// The detail is a caller-owned opaque reference (observed value digest, handle
/// ref, or question ref). This crate never reads the underlying path, marker,
// or remote.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityEvidence {
    pub class: SupportingEvidenceClass,
    pub detail_ref: String,
    pub standing: EvidenceStanding,
}

/// Explicit memory-applicability class across clones of one lineage.
///
/// A lineage match may propose reuse of `lineage_portable` records only.
/// Workspace-instance-bound and task-bound state never travels merely because
/// Git history overlaps.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryApplicability {
    LineagePortable,
    WorkspaceInstanceBound,
    TaskBound,
}

/// Versioned, resource-identified `WorkScope` descriptor (I4.1).
///
/// Identity comes from [`ScopeFingerprint`]; every other field is either
/// generation/fence evidence, supporting display/policy metadata, or the exact
/// resource bindings that later resolver and guard slices consume.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkScopeDescriptor {
    pub scope_ref: String,
    pub descriptor_revision: u64,
    pub kind: ScopeKind,
    pub display_name: String,
    pub lineage: Option<RepositoryLineageIdentity>,
    pub instances: Vec<WorkspaceInstanceIdentity>,
    pub owner_refs: Vec<String>,
    pub canonical_resource_refs: Vec<String>,
    pub root_identities: Vec<String>,
    pub external_resource_refs: Vec<String>,
    pub truth_surface_refs: Vec<String>,
    pub verifier_refs: Vec<String>,
    pub privacy: PrivacyProfile,
    pub authority_profile_ref: Option<String>,
    pub execution_identity: ResourceExecutionIdentity,
    pub generation: GenerationEvidence,
    pub state_fence: StateFence,
    pub available_capabilities: Vec<String>,
    pub missing_capabilities: Vec<String>,
    pub lifecycle: ScopeLifecycle,
}

/// Source that produced a [`WorkScopeProposal`].
///
/// The source records provenance for the later resolver-ordering slice; it
/// grants no priority by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProposalSource {
    Human,
    Host,
    ResumedTask,
    Scanner,
    Adapter,
}

/// Authenticated scope proposal (I4.3.1).
///
/// An explicit path, project name, or host hint enters here as
/// [`IdentityEvidence`], never as authority. Only entries in
/// `authenticated_identities` may later resolve to an authenticated binding;
/// everything else stays a discriminative hint for the resolver-ordering slice.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkScopeProposal {
    pub proposal_ref: String,
    pub proposer_ref: String,
    pub proposed_kind: ScopeKind,
    pub proposed_lineage: Option<RepositoryLineageIdentity>,
    pub proposed_instances: Vec<WorkspaceInstanceIdentity>,
    pub source: ProposalSource,
    pub authenticated_identities: Vec<String>,
    pub supporting_evidence: Vec<IdentityEvidence>,
    pub competing_candidate_refs: Vec<String>,
    pub requested_privacy: Option<PrivacyProfile>,
    pub requested_authority_profile_ref: Option<String>,
}

/// Whether a [`WorkScopeResolutionReceipt`] carries proven or provisional binding.
///
/// Unambiguous is not equivalent to authenticated: a provisional receipt keeps
/// full candidate evidence but cannot admit Material effects; dependent calls
/// fail with `WORKSCOPE_UNAUTHENTICATED` until an authenticated receipt exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolutionAuthentication {
    Authenticated,
    Provisional,
}

/// Durable resolution receipt (I4.3.1).
///
/// Records the selected scope identity and generation, the fingerprint actually
/// matched, supporting evidence, rejected and unresolved candidates, the
/// owner/policy authority behind the decision, and the fencing state. Later
/// resolver and guard slices produce and revalidate this receipt; this slice
/// only fixes its durable shape.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkScopeResolutionReceipt {
    pub receipt_ref: String,
    pub proposal_ref: String,
    pub selected: ScopeIdentity,
    pub fingerprint: ScopeFingerprint,
    pub authentication: ResolutionAuthentication,
    pub supporting_evidence: Vec<IdentityEvidence>,
    pub rejected_candidate_refs: Vec<String>,
    pub unresolved_candidate_refs: Vec<String>,
    pub authority_ref: String,
    pub state_fence: StateFence,
}

/// What an authorized relocation/attach receipt records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeRelocationKind {
    Move,
    AdditionalClone,
    Attach,
}

/// Authorized move/clone/attach receipt (I4.1).
///
/// A confirmed move or additional clone creates this receipt; it preserves the
/// prior workspace-instance identity (old root identity and task history are
/// never rewritten) and binds the newly observed instance under explicit
/// authorization. Acceptance-time admission of the observed instance and its
/// generation fence is a later slice that consumes this receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeRelocationOrAttachReceipt {
    pub receipt_ref: String,
    pub kind: ScopeRelocationKind,
    pub scope_ref: String,
    pub scope_kind: ScopeKind,
    pub lineage: RepositoryLineageIdentity,
    pub prior_instance: WorkspaceInstanceIdentity,
    pub observed_instance: WorkspaceInstanceIdentity,
    pub authorizing_ref: String,
    pub state_fence: StateFence,
}

fn optional_text(value: Option<&String>, field: &'static str) -> Result<(), WorkScopeError> {
    if let Some(text_value) = value {
        text(text_value, field)?;
    }
    Ok(())
}

fn text_collection(values: &[String], field: &'static str) -> Result<(), WorkScopeError> {
    for value in values {
        text(value, field)?;
    }
    unique(values.iter(), field)
}

fn evidence_item(item: &IdentityEvidence) -> Result<(), WorkScopeError> {
    text(&item.detail_ref, "evidence.detail_ref")
}

impl GenerationEvidence {
    /// Validates generation/fence evidence without treating it as identity.
    ///
    /// # Errors
    ///
    /// Returns an error when an optional branch, commit, or dirty-summary
    /// reference is blank or contains control characters.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        optional_text(self.branch_ref.as_ref(), "generation.branch_ref")?;
        optional_text(self.commit_ref.as_ref(), "generation.commit_ref")?;
        optional_text(
            self.dirty_summary_ref.as_ref(),
            "generation.dirty_summary_ref",
        )
    }
}

impl ScopeFingerprint {
    /// Derives the deterministic identity fingerprint for one descriptor.
    ///
    /// Only stable resource identities enter the derivation: scope reference,
    /// kind, lineage evidence, workspace-instance evidence, and
    /// canonical/external resource references. Display name, generation
    /// evidence, descriptor revision, lifecycle, privacy, authority,
    /// capabilities, and fence are excluded, so none of them can merge, split,
    /// or rename a scope.
    #[must_use]
    pub fn derive_for(descriptor: &WorkScopeDescriptor) -> Self {
        const DOMAIN: &str = "workscope-identity-v1";
        let scope_ref = descriptor.scope_ref.as_str();
        let mut parts = vec![
            format!("domain={DOMAIN}"),
            format!("scope_ref={scope_ref}"),
            format!("kind={}", scope_kind_token(descriptor.kind)),
        ];
        if let Some(lineage) = &descriptor.lineage {
            let lineage_ref = lineage.lineage_ref.as_str();
            let object_store_ref = lineage.object_store_ref.as_str();
            let initial_history_ref = lineage.initial_history_ref.as_str();
            parts.push(format!("lineage_ref={lineage_ref}"));
            parts.push(format!("object_store_ref={object_store_ref}"));
            parts.push(format!("initial_history_ref={initial_history_ref}"));
            if let Some(remote) = &lineage.normalized_remote_ref {
                parts.push(format!("normalized_remote_ref={remote}"));
            }
            if let Some(manifest) = &lineage.manifest_identity_ref {
                parts.push(format!("manifest_identity_ref={manifest}"));
            }
        }
        let mut instances = descriptor.instances.clone();
        instances.sort_by(|left, right| left.instance_ref.cmp(&right.instance_ref));
        for instance in &instances {
            let instance_ref = instance.instance_ref.as_str();
            let root_identity = instance.root_identity.as_str();
            let vcs_identity = instance.vcs_identity_ref.as_deref().unwrap_or("");
            let generation = instance.generation;
            parts.push(format!(
                "instance={instance_ref}\u{1f}{root_identity}\u{1f}{vcs_identity}\u{1f}{generation}"
            ));
        }
        let mut canonical = descriptor.canonical_resource_refs.clone();
        canonical.sort();
        for resource in &canonical {
            parts.push(format!("canonical_resource_ref={resource}"));
        }
        let mut external = descriptor.external_resource_refs.clone();
        external.sort();
        for resource in &external {
            parts.push(format!("external_resource_ref={resource}"));
        }
        Self {
            value: parts.join("\n"),
        }
    }

    /// Validates that a fingerprint value is present and well-formed.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is blank or contains control characters.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.value, "fingerprint.value")
    }
}

fn scope_kind_token(kind: ScopeKind) -> &'static str {
    match kind {
        ScopeKind::GitRepo => "git_repo",
        ScopeKind::Directory => "directory",
        ScopeKind::DocumentSet => "document_set",
        ScopeKind::Service => "service",
        ScopeKind::RemoteSystem => "remote_system",
        ScopeKind::GuiWorkspace => "gui_workspace",
        ScopeKind::ResearchCorpus => "research_corpus",
        ScopeKind::Composite => "composite",
        ScopeKind::AdHoc => "ad_hoc",
        ScopeKind::EliotSystem => "eliot_system",
    }
}

impl WorkScopeDescriptor {
    /// Returns the identity fingerprint derived from stable resources.
    #[must_use]
    pub fn fingerprint(&self) -> ScopeFingerprint {
        ScopeFingerprint::derive_for(self)
    }

    /// Validates the descriptor shape without authenticating any binding.
    ///
    /// # Errors
    ///
    /// Returns an error when identity references are blank, the descriptor
    /// revision is zero, the instance set is empty or duplicated, a reference
    /// collection holds blanks or duplicates, one capability is both available
    /// and missing, lineage/instance/privacy evidence is invalid, or the state
    /// fence is invalid.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.scope_ref, "scope_ref")?;
        counter(self.descriptor_revision, "descriptor_revision")?;
        text(&self.display_name, "display_name")?;
        if let Some(lineage) = &self.lineage {
            lineage.validate()?;
        }
        if self.instances.is_empty() {
            return Err(WorkScopeError::EmptyCollection { field: "instances" });
        }
        for instance in &self.instances {
            instance.validate()?;
        }
        unique(
            self.instances.iter().map(|instance| &instance.instance_ref),
            "instances",
        )?;
        text_collection(&self.owner_refs, "owner_refs")?;
        text_collection(&self.canonical_resource_refs, "canonical_resource_refs")?;
        text_collection(&self.root_identities, "root_identities")?;
        text_collection(&self.external_resource_refs, "external_resource_refs")?;
        text_collection(&self.truth_surface_refs, "truth_surface_refs")?;
        text_collection(&self.verifier_refs, "verifier_refs")?;
        text_collection(&self.available_capabilities, "available_capabilities")?;
        text_collection(&self.missing_capabilities, "missing_capabilities")?;
        if self
            .available_capabilities
            .iter()
            .any(|capability| self.missing_capabilities.contains(capability))
        {
            return Err(WorkScopeError::DuplicateReference {
                field: "available_and_missing_capabilities",
            });
        }
        self.privacy.validate()?;
        optional_text(self.authority_profile_ref.as_ref(), "authority_profile_ref")?;
        if let ResourceExecutionIdentity::InteractiveUser { sid_ref } = &self.execution_identity {
            text(sid_ref, "execution_identity.sid_ref")?;
        }
        self.generation.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| WorkScopeError::InvalidStateFence)?;
        Ok(())
    }
}

impl WorkScopeProposal {
    /// Validates the proposal shape without resolving or authenticating it.
    ///
    /// # Errors
    ///
    /// Returns an error when proposal or proposer references are blank,
    /// proposed lineage/instance evidence is invalid, an authenticated identity
    /// or competing reference is blank or duplicated, supporting evidence is
    /// blank, or requested privacy/authority references are invalid.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.proposal_ref, "proposal_ref")?;
        text(&self.proposer_ref, "proposer_ref")?;
        if let Some(lineage) = &self.proposed_lineage {
            lineage.validate()?;
        }
        for instance in &self.proposed_instances {
            instance.validate()?;
        }
        unique(
            self.proposed_instances
                .iter()
                .map(|instance| &instance.instance_ref),
            "proposed_instances",
        )?;
        text_collection(&self.authenticated_identities, "authenticated_identities")?;
        for item in &self.supporting_evidence {
            evidence_item(item)?;
        }
        text_collection(&self.competing_candidate_refs, "competing_candidate_refs")?;
        if let Some(privacy) = &self.requested_privacy {
            privacy.validate()?;
        }
        optional_text(
            self.requested_authority_profile_ref.as_ref(),
            "requested_authority_profile_ref",
        )
    }
}

impl WorkScopeResolutionReceipt {
    /// Validates the receipt shape without granting authority.
    ///
    /// # Errors
    ///
    /// Returns an error when receipt, proposal, authority, or fingerprint
    /// references are blank, the selected identity is invalid, supporting
    /// evidence is blank, rejected/unresolved candidate sets hold blanks or
    /// duplicates, the selected scope appears among rejected or unresolved
    /// candidates, or the state fence is invalid.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.receipt_ref, "receipt_ref")?;
        text(&self.proposal_ref, "proposal_ref")?;
        self.selected.validate()?;
        self.fingerprint.validate()?;
        for item in &self.supporting_evidence {
            evidence_item(item)?;
        }
        text_collection(&self.rejected_candidate_refs, "rejected_candidate_refs")?;
        text_collection(&self.unresolved_candidate_refs, "unresolved_candidate_refs")?;
        if self
            .rejected_candidate_refs
            .iter()
            .any(|candidate| candidate == &self.selected.scope_ref)
            || self
                .unresolved_candidate_refs
                .iter()
                .any(|candidate| candidate == &self.selected.scope_ref)
        {
            return Err(WorkScopeError::DuplicateReference {
                field: "selected_and_candidate_refs",
            });
        }
        if self
            .rejected_candidate_refs
            .iter()
            .any(|candidate| self.unresolved_candidate_refs.contains(candidate))
        {
            return Err(WorkScopeError::DuplicateReference {
                field: "rejected_and_unresolved_candidate_refs",
            });
        }
        text(&self.authority_ref, "authority_ref")?;
        self.state_fence
            .validate()
            .map_err(|_| WorkScopeError::InvalidStateFence)
    }
}

impl ScopeRelocationOrAttachReceipt {
    /// Validates the receipt shape without admitting the observed instance.
    ///
    /// The prior instance is preserved verbatim so a wrong historical binding
    /// can be corrected without rewriting history; admission of the observed
    /// instance and its generation fence belongs to a later slice.
    ///
    /// # Errors
    ///
    /// Returns an error when receipt, scope, authorizing, lineage, or instance
    /// references are blank, or the state fence is invalid.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.receipt_ref, "receipt_ref")?;
        text(&self.scope_ref, "scope_ref")?;
        self.lineage.validate()?;
        self.prior_instance.validate()?;
        self.observed_instance.validate()?;
        text(&self.authorizing_ref, "authorizing_ref")?;
        self.state_fence
            .validate()
            .map_err(|_| WorkScopeError::InvalidStateFence)
    }
}
