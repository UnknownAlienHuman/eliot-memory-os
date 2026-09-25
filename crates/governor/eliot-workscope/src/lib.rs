//! Pure `WorkScope` resolution and binding contracts.
//!
//! This crate only evaluates caller-supplied observations. It does not inspect
//! filesystems, processes, repositories, credentials, stores or task authority.

use std::collections::BTreeSet;

use eliot_contracts::StateFence;
use eliot_security_contracts::{
    FreshnessStatus, IntegrityStatus, ObservationDomainRef, PrivacyClass, QuarantineState,
    SourceAssurance,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod caller;
mod governance;
mod guard;
mod identity;
mod issuance;
mod readiness;
mod resolver;
mod scanner;
mod transition;

pub use caller::{
    DescriptorPolicy, ObservedScopeResources, ReceiptAdmission, TriggerAdmission, WithholdReason,
    admit_at_trigger, describe_observed_scope, propose_scope, verify_receipt_for_admission,
};
pub use governance::{
    AuthorityBasis, GoverningSourceAdmission, GoverningSourceCandidate, NewSourceCandidate,
    NewTaskIntake, PrecedenceDeclaration, SourceAdmissionRequest, SourceCandidateOrigin,
    SourceConflictSet, SourceCoverage, SourceReadiness, TaskIntakeCandidate, TaskIntakeOrigin,
    TaskSelectionRequired, admit_governing_sources, source_readiness, task_selection_required,
};
pub use guard::{
    GuardTrigger, GuardVerdict, IdentityLegOutcome, TriggerReport, check_at_trigger, identity_legs,
    produce_attach_receipt, rebind_with_receipt,
};
pub use identity::{
    EvidenceStanding, GenerationEvidence, IdentityEvidence, MemoryApplicability, ProposalSource,
    ResolutionAuthentication, ResourceExecutionIdentity, ScopeFingerprint, ScopeLifecycle,
    ScopeRelocationKind, ScopeRelocationOrAttachReceipt, SupportingEvidenceClass,
    WorkScopeDescriptor, WorkScopeProposal, WorkScopeResolutionReceipt,
};
pub use issuance::{
    IssuanceRefusal, admit_initial_binding, issuance_refusal, issue_resolution_receipt,
};
pub use readiness::{
    ExplicitAbsenceRecord, GoverningCoverage, MaterialAdmission, MaterialReadinessDirective,
    MaterialReadinessInputs, MaterialReadinessReport, RequestedEffect, allowed_effects,
    assess_material_readiness, evaluate_material_request,
};
pub use resolver::{
    BindingToken, HostObservedHandles, ManifestBoundaryClaim, RegisteredInstanceEvidence,
    ResolutionOutcome, ResolutionRequest, ResolutionTier, ResumedTaskEvidence, SessionTaskClaim,
    WorkScopeResolver,
};
pub use scanner::{
    AdapterEvidence, ArtifactDirEvidence, BootstrapDiscoveryInputs, BootstrapScanEvidence,
    BootstrapScanOutcome, BootstrapScanner, ChangeSummary, DiscoveryLeaseKey,
    DiscoveryLeaseRequest, DiscoveryOperation, EditorWorkspaceEvidence, ExistingRecordEvidence,
    FileTypeCount, ForbiddenScanClass, MAX_DISCOVERY_CONSUMPTION, ManifestEvidence,
    OnboardingRecommendation, PrivacyBoundary, ProvisionalScopeProfile, RegisteredBuildProfile,
    RootServiceEvidence, SCAN_PRIVACY_BOUNDARY_REQUIRED, ScanDisclosureReceipt,
    ScanDisclosureStore, ScanReceiptHandle, ScannerResolverInputs, authorize_operation,
    candidate_source_roles, derive_lease_ref, issue_discovery_lease, run_bootstrap_discovery,
};
pub use transition::{
    CandidateRecordStanding, ScopeTransition, ScopeTransitionKind, ScopeTransitionReceipt,
    ScopeTransitionStep, StagedCandidateRecord, TRANSITION_STEP_COUNT, TransitionFailure,
    TransitionObservation, TransitionStepEvidence, TransitionStepOutcome, attach_post_commit_guard,
    execute_transition, observe_transition, propose_transition, resume_transition,
};

/// Returns whether a retained binding describes a resource descriptor.
///
/// Identity comparison covers scope reference, kind, lineage reference,
/// admission generation, and exact instance/root membership. It never
/// consults display names, proximity, recency, manifest names, copied
/// markers, or remote URLs.
pub(crate) fn binding_matches_descriptor(
    binding: &ScopeBinding,
    descriptor: &identity::WorkScopeDescriptor,
) -> bool {
    binding.scope.scope_ref == descriptor.scope_ref
        && binding.scope.kind == descriptor.kind
        && binding.scope.lineage_ref
            == descriptor
                .lineage
                .as_ref()
                .map(|lineage| lineage.lineage_ref.clone())
        && binding.scope.generation == descriptor.generation.resource_generation.value()
        && descriptor.instances.iter().any(|instance| {
            instance.instance_ref == binding.scope.instance_ref
                && instance.root_identity == binding.scope.root_identity
        })
}

/// The bounded kind of a `WorkScope`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    GitRepo,
    Directory,
    DocumentSet,
    Service,
    RemoteSystem,
    GuiWorkspace,
    ResearchCorpus,
    Composite,
    AdHoc,
    EliotSystem,
}

/// Stable identity of the scope and its exact workspace instance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeIdentity {
    pub scope_ref: String,
    pub kind: ScopeKind,
    pub lineage_ref: Option<String>,
    pub instance_ref: String,
    pub root_identity: String,
    pub generation: u64,
}

/// Repository identity independent from a checkout's local instance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepositoryLineageIdentity {
    pub lineage_ref: String,
    pub object_store_ref: String,
    pub initial_history_ref: String,
    pub normalized_remote_ref: Option<String>,
    pub manifest_identity_ref: Option<String>,
}

/// Exact checkout/resource identity. Paths are represented by caller-owned
/// opaque identity values; this crate never reads or normalizes them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceInstanceIdentity {
    pub instance_ref: String,
    pub root_identity: String,
    pub vcs_identity_ref: Option<String>,
    pub generation: u64,
}

/// Evidence-backed candidate, not an authenticated authority binding.
///
/// `descriptor_revision` is the `WorkScopeDescriptor` revision this candidate
/// was observed at; the binding-token tier (I4.2 step 2) names exactly this
/// revision, so a token for a superseded revision never resolves here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkScopeCandidate {
    pub scope: ScopeIdentity,
    pub descriptor_revision: u64,
    pub lineage: Option<RepositoryLineageIdentity>,
    pub instance: WorkspaceInstanceIdentity,
    pub privacy_class: PrivacyClass,
}

/// Why a candidate set cannot be selected automatically.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateDisposition {
    Unique,
    Ambiguous,
    NewScope,
    StaleBinding,
    Conflicted,
}

/// Deterministically ordered observations of possible scopes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkScopeCandidateSet {
    pub observed_root_ref: String,
    pub candidates: Vec<WorkScopeCandidate>,
    pub disposition: CandidateDisposition,
    pub disambiguation_ref: Option<String>,
}

/// Read classes admitted by a short-lived discovery lease.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryRead {
    FilesystemIdentity,
    VcsIdentity,
    ManifestNamesAndHashes,
    KnownFormatHeaders,
    GoverningSourceCandidates,
}

/// A bounded, non-authoritative discovery lease.
///
/// The lease is keyed to one proposer/session/host and one candidate-root
/// filesystem identity: those four key components are retained on the lease
/// so every use re-derives the lease reference and verifies the key binding
/// through `DiscoveryReadLease::key_matches` before charging. A lease whose
/// reference does not re-derive from the presented key is rejected without
/// consumption.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryReadLease {
    pub lease_ref: String,
    pub proposer_ref: String,
    pub session_ref: String,
    pub host_ref: String,
    pub root_filesystem_identity_ref: String,
    pub candidate_root_ref: String,
    pub allowed_reads: Vec<DiscoveryRead>,
    pub deadline: u64,
    pub consumption_limit: u32,
    pub consumed: u32,
}

/// Cold-start compiler lease for one exact lineage/instance/source generation.
/// It carries no task or authority identity and cannot grant material effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OnboardingLeaseState {
    Discovering,
    Resolving,
    Compiling,
    Ready,
    Ambiguous,
    Failed,
    Expired,
}

/// Deterministic single-flight onboarding lease.
///
/// The lease key is the exact triple of workspace filesystem/VCS identity
/// (`lineage_candidate_ref` + `workspace_instance_candidate_ref`), privacy
/// boundary (`privacy_class`) and governing-source generation. Compatible
/// callers share one key and join the same lease; any difference in identity,
/// boundary or generation never coalesces.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OnboardingLease {
    pub lease_ref: String,
    pub lineage_candidate_ref: String,
    pub workspace_instance_candidate_ref: String,
    pub privacy_class: PrivacyClass,
    pub governing_source_generation: u64,
    pub compiler_epoch: u64,
    pub state: OnboardingLeaseState,
    pub deadline: u64,
}

impl OnboardingLease {
    /// Validates the lease without making it an authority or task binding.
    ///
    /// # Errors
    ///
    /// Returns an error when identity references or generation/deadline values
    /// are blank or zero.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.lease_ref, "lease_ref")?;
        text(&self.lineage_candidate_ref, "lineage_candidate_ref")?;
        text(
            &self.workspace_instance_candidate_ref,
            "workspace_instance_candidate_ref",
        )?;
        counter(
            self.governing_source_generation,
            "governing_source_generation",
        )?;
        counter(self.compiler_epoch, "compiler_epoch")?;
        counter(self.deadline, "deadline")
    }

    /// Returns whether this lease may still advance at the supplied tick.
    #[must_use]
    pub fn is_active(&self, now: u64) -> bool {
        now <= self.deadline
            && matches!(
                self.state,
                OnboardingLeaseState::Discovering
                    | OnboardingLeaseState::Resolving
                    | OnboardingLeaseState::Compiling
            )
    }

    /// Returns whether two leases share one single-flight key: exact workspace
    /// filesystem/VCS identity plus privacy boundary plus governing-source
    /// generation. Lease references, epochs, states and deadlines never merge
    /// or split a key.
    #[must_use]
    pub fn key_matches(&self, other: &OnboardingLease) -> bool {
        self.lineage_candidate_ref == other.lineage_candidate_ref
            && self.workspace_instance_candidate_ref == other.workspace_instance_candidate_ref
            && self.privacy_class == other.privacy_class
            && self.governing_source_generation == other.governing_source_generation
    }
}

/// Lease failures are typed and never trigger a broader read or fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum DiscoveryLeaseError {
    #[error("discovery lease is expired")]
    Expired,
    #[error("discovery read is not admitted by the lease")]
    ReadNotAdmitted,
    #[error("discovery lease consumption limit reached")]
    ConsumptionLimit,
}

/// Governing-source role declared by the applicable project source model.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GoverningSourceRole {
    UserTask,
    Architecture,
    Implementation,
    AgentInstruction,
    BuildTestContract,
    DomainPolicy,
    SupportingReference,
}

/// Admission state for one source candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Admitted,
    Candidate,
    Stale,
    Superseded,
    Conflicted,
    Unavailable,
}

/// One source with provider-owned assurance and disclosure-domain evidence.
///
/// `source_ref` is the exact handle and `digest` the exact content digest of
/// the admitted snapshot; `authority_basis` names the owner or contract that
/// promoted the candidate, and is `None` until an applicable authority does so.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoverningSource {
    pub source_ref: String,
    pub role: GoverningSourceRole,
    pub assurance: SourceAssurance,
    pub applicable_generation: u64,
    pub status: SourceStatus,
    pub domains: Vec<ObservationDomainRef>,
    pub digest: String,
    pub authority_basis: Option<AuthorityBasis>,
}

/// Deterministic governing-source set for one scope generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoverningSourceSet {
    pub scope_ref: String,
    pub generation: u64,
    pub sources: Vec<GoverningSource>,
    pub unresolved_conflict_refs: Vec<String>,
}

/// Privacy constraints applied before a source can become governing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyProfile {
    pub admitted_classes: Vec<PrivacyClass>,
}

/// Typed resolver outcomes; no branch chooses a candidate silently.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "disposition", content = "detail")]
pub enum ScopeResolution {
    Unique(Box<WorkScopeCandidate>),
    Ambiguous(Box<WorkScopeCandidateSet>),
    NewScope,
    StaleBinding,
    Conflicted,
}

/// Cold-start readiness without task or authority identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "disposition", content = "detail")]
pub enum OnboardingOutcome {
    ReadyReadOnly {
        scope: Box<WorkScopeCandidate>,
        governing_sources: Box<GoverningSourceSet>,
        lease_ref: String,
    },
    NeedsScope(Box<WorkScopeCandidateSet>),
    NeedsSources,
    Ambiguous(Box<WorkScopeCandidateSet>),
    Degraded(OnboardingDegraded),
}

/// Explicit degraded onboarding state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OnboardingDegraded {
    DiscoveryLeaseExpired,
    DiscoveryLeaseDenied,
    PrivacyDenied,
    InvalidSourceEvidence,
}

/// Expected and observed values checked by [`ScopeBindingGuard`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeBinding {
    pub scope: ScopeIdentity,
    pub privacy_class: PrivacyClass,
    pub governing_source_generation: u64,
}

/// Mid-task revalidation disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScopeBindingDisposition {
    Matched,
    StaleBinding,
    DifferentInstance,
    Ambiguous,
    ProvisionalRebind,
    Conflicted,
}

/// Pure receipt of one binding check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeBindingGuardReceipt {
    pub expected_scope_ref: String,
    pub observed_scope_ref: String,
    pub expected_lineage_ref: Option<String>,
    pub observed_lineage_ref: Option<String>,
    pub expected_instance_ref: String,
    pub observed_instance_ref: String,
    pub disposition: ScopeBindingDisposition,
    pub source_generation: u64,
}

/// The persisted, exact current `WorkScope` binding owned by the governor.
///
/// This is a closed snapshot: it carries no task, plan, session, principal or
/// kernel-generation authority.  Admission and recovery validate the guard
/// receipt against the retained binding before exposing the snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkScopeBindingSnapshot {
    pub state_fence: StateFence,
    pub owner_revision: u64,
    pub binding: ScopeBinding,
    pub guard_receipt: ScopeBindingGuardReceipt,
}

/// The canonical owner for one current `WorkScope` binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkScopeBindingOwner {
    snapshot: WorkScopeBindingSnapshot,
}

/// Validation errors for the bounded core.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum WorkScopeError {
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} must be non-zero")]
    InvalidCounter { field: &'static str },
    #[error("{field} must not contain duplicates")]
    DuplicateReference { field: &'static str },
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    #[error("source assurance is invalid")]
    InvalidSourceEvidence,
    #[error("source identity does not match its assurance")]
    SourceIdentityMismatch,
    #[error("source set is not admitted for this scope generation")]
    SourceSetMismatch,
    #[error("governing sources are conflicted with no admitted winner")]
    UnresolvedSourceConflict,
    #[error("task promotion requires the decision owner or a delegated binding")]
    TaskAuthorityDenied,
    #[error("source privacy class is outside the admitted boundary")]
    PrivacyDenied,
    #[error("state fence is invalid")]
    InvalidStateFence,
    #[error("state fence does not match the retained binding")]
    StateFenceMismatch,
    #[error("scope binding guard receipt is not matched")]
    BindingReceiptNotMatched,
    #[error("scope binding guard receipt does not match the retained binding")]
    BindingReceiptMismatch,
}

fn text(value: &str, field: &'static str) -> Result<(), WorkScopeError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(WorkScopeError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn counter(value: u64, field: &'static str) -> Result<(), WorkScopeError> {
    (value != 0)
        .then_some(())
        .ok_or(WorkScopeError::InvalidCounter { field })
}

pub(crate) fn digest(value: &str, field: &'static str) -> Result<(), WorkScopeError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(WorkScopeError::InvalidDigest { field })
    }
}

fn unique<I>(values: I, field: &'static str) -> Result<(), WorkScopeError>
where
    I: IntoIterator,
    I::Item: Ord,
{
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .all(|value| seen.insert(value))
        .then_some(())
        .ok_or(WorkScopeError::DuplicateReference { field })
}

impl ScopeIdentity {
    /// Validates identity-bearing fields without interpreting their values.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity is blank, contains control characters,
    /// or has a zero generation.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.scope_ref, "scope_ref")?;
        text(&self.instance_ref, "instance_ref")?;
        text(&self.root_identity, "root_identity")?;
        if let Some(lineage) = &self.lineage_ref {
            text(lineage, "lineage_ref")?;
        }
        counter(self.generation, "generation")
    }
}

impl RepositoryLineageIdentity {
    /// Validates opaque lineage evidence; it does not authenticate a scope.
    ///
    /// # Errors
    ///
    /// Returns an error when an evidence reference is blank or contains control
    /// characters.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.lineage_ref, "lineage_ref")?;
        text(&self.object_store_ref, "object_store_ref")?;
        text(&self.initial_history_ref, "initial_history_ref")?;
        if let Some(remote) = &self.normalized_remote_ref {
            text(remote, "normalized_remote_ref")?;
        }
        if let Some(manifest) = &self.manifest_identity_ref {
            text(manifest, "manifest_identity_ref")?;
        }
        Ok(())
    }
}

impl WorkspaceInstanceIdentity {
    /// Validates exact instance evidence without reading the underlying root.
    ///
    /// # Errors
    ///
    /// Returns an error when an instance reference is blank, contains control
    /// characters, or has a zero generation.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.instance_ref, "instance_ref")?;
        text(&self.root_identity, "root_identity")?;
        if let Some(vcs) = &self.vcs_identity_ref {
            text(vcs, "vcs_identity_ref")?;
        }
        counter(self.generation, "instance.generation")
    }
}

impl WorkScopeCandidateSet {
    /// Builds a deterministic candidate set and preserves all candidates.
    ///
    /// # Errors
    ///
    /// Returns an error when candidate identities are invalid, duplicated, or
    /// carry inconsistent lineage evidence.
    pub fn new(
        observed_root_ref: impl Into<String>,
        mut candidates: Vec<WorkScopeCandidate>,
        disposition: CandidateDisposition,
        disambiguation_ref: Option<String>,
    ) -> Result<Self, WorkScopeError> {
        let observed_root_ref = observed_root_ref.into();
        text(&observed_root_ref, "observed_root_ref")?;
        for candidate in &candidates {
            candidate.scope.validate()?;
            counter(
                candidate.descriptor_revision,
                "candidate.descriptor_revision",
            )?;
            candidate.instance.validate()?;
            if let Some(lineage) = &candidate.lineage {
                lineage.validate()?;
                if candidate.scope.lineage_ref.as_deref() != Some(lineage.lineage_ref.as_str()) {
                    return Err(WorkScopeError::SourceSetMismatch);
                }
            }
        }
        candidates.sort_by(|left, right| {
            left.scope
                .scope_ref
                .cmp(&right.scope.scope_ref)
                .then(left.scope.instance_ref.cmp(&right.scope.instance_ref))
        });
        unique(
            candidates
                .iter()
                .map(|candidate| (&candidate.scope.scope_ref, &candidate.scope.instance_ref)),
            "candidate identities",
        )?;
        if let Some(ref value) = disambiguation_ref {
            text(value, "disambiguation_ref")?;
        }
        Ok(Self {
            observed_root_ref,
            candidates,
            disposition,
            disambiguation_ref,
        })
    }

    /// Applies the explicit disposition without selecting a near match.
    #[must_use]
    pub fn resolve(&self) -> ScopeResolution {
        match self.disposition {
            CandidateDisposition::Unique if self.candidates.len() == 1 => {
                ScopeResolution::Unique(Box::new(self.candidates[0].clone()))
            }
            CandidateDisposition::NewScope => ScopeResolution::NewScope,
            CandidateDisposition::StaleBinding => ScopeResolution::StaleBinding,
            CandidateDisposition::Conflicted => ScopeResolution::Conflicted,
            CandidateDisposition::Unique | CandidateDisposition::Ambiguous => {
                ScopeResolution::Ambiguous(Box::new(self.clone()))
            }
        }
    }
}

impl DiscoveryReadLease {
    /// Validates the lease's bounded, ephemeral shape.
    ///
    /// # Errors
    ///
    /// Returns an error when lease references are invalid, counters are zero or
    /// reads are duplicated.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.lease_ref, "lease_ref")?;
        text(&self.proposer_ref, "lease.proposer_ref")?;
        text(&self.session_ref, "lease.session_ref")?;
        text(&self.host_ref, "lease.host_ref")?;
        text(
            &self.root_filesystem_identity_ref,
            "lease.root_filesystem_identity_ref",
        )?;
        text(&self.candidate_root_ref, "candidate_root_ref")?;
        counter(self.deadline, "deadline")?;
        counter(u64::from(self.consumption_limit), "consumption_limit")?;
        if self.consumed > self.consumption_limit {
            return Err(WorkScopeError::InvalidCounter { field: "consumed" });
        }
        unique(self.allowed_reads.iter(), "allowed_reads")
    }

    /// Checks one requested class at a caller-supplied monotonic tick.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the deadline, consumption limit, or admitted
    /// read set rejects the request.
    pub fn authorize(&self, requested: DiscoveryRead, now: u64) -> Result<(), DiscoveryLeaseError> {
        if now > self.deadline {
            return Err(DiscoveryLeaseError::Expired);
        }
        if self.consumed >= self.consumption_limit {
            return Err(DiscoveryLeaseError::ConsumptionLimit);
        }
        if self.allowed_reads.contains(&requested) {
            Ok(())
        } else {
            Err(DiscoveryLeaseError::ReadNotAdmitted)
        }
    }
}

impl PrivacyProfile {
    /// Validates and deterministically admits only the declared classes.
    ///
    /// # Errors
    ///
    /// Returns an error when no class is admitted or a class is duplicated.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        if self.admitted_classes.is_empty() {
            return Err(WorkScopeError::EmptyCollection {
                field: "admitted_classes",
            });
        }
        if self
            .admitted_classes
            .iter()
            .enumerate()
            .any(|(index, class)| self.admitted_classes[..index].contains(class))
        {
            return Err(WorkScopeError::DuplicateReference {
                field: "admitted_classes",
            });
        }
        Ok(())
    }

    /// Returns whether the source class is explicitly inside this boundary.
    #[must_use]
    pub fn admits(&self, class: PrivacyClass) -> bool {
        self.admitted_classes.contains(&class)
    }
}

impl GoverningSourceSet {
    /// Normalizes source order and rejects duplicate source identities.
    ///
    /// # Errors
    ///
    /// Returns an error when source identity, generation, assurance, or domain
    /// evidence is invalid or duplicated.
    pub fn new(
        scope_ref: impl Into<String>,
        generation: u64,
        mut sources: Vec<GoverningSource>,
        unresolved_conflict_refs: Vec<String>,
    ) -> Result<Self, WorkScopeError> {
        let scope_ref = scope_ref.into();
        text(&scope_ref, "scope_ref")?;
        counter(generation, "generation")?;
        unique(unresolved_conflict_refs.iter(), "unresolved_conflict_refs")?;
        for source in &sources {
            text(&source.source_ref, "source_ref")?;
            counter(source.applicable_generation, "applicable_generation")?;
            digest(&source.digest, "source.digest")?;
            if let Some(basis) = &source.authority_basis {
                basis.validate()?;
            }
            if source.source_ref != source.assurance.source_ref {
                return Err(WorkScopeError::SourceIdentityMismatch);
            }
            source
                .assurance
                .validate()
                .map_err(|_| WorkScopeError::InvalidSourceEvidence)?;
            for domain in &source.domains {
                domain
                    .validate()
                    .map_err(|_| WorkScopeError::InvalidSourceEvidence)?;
            }
        }
        sources.sort_by(|left, right| {
            left.source_ref
                .cmp(&right.source_ref)
                .then(left.role.cmp(&right.role))
        });
        unique(
            sources.iter().map(|source| &source.source_ref),
            "source_ref",
        )?;
        Ok(Self {
            scope_ref,
            generation,
            sources,
            unresolved_conflict_refs,
        })
    }

    /// Checks source status, generation and provider-owned privacy assurance.
    ///
    /// # Errors
    ///
    /// Returns an error when the source set is stale, conflicted, outside the
    /// privacy boundary, or fails provider assurance validation.
    pub fn validate_for(
        &self,
        scope: &ScopeIdentity,
        privacy: &PrivacyProfile,
    ) -> Result<(), WorkScopeError> {
        scope.validate()?;
        privacy.validate()?;
        if self.scope_ref != scope.scope_ref || self.generation != scope.generation {
            return Err(WorkScopeError::SourceSetMismatch);
        }
        if !self.unresolved_conflict_refs.is_empty()
            || self
                .sources
                .iter()
                .any(|source| source.status != SourceStatus::Admitted)
        {
            return Err(WorkScopeError::SourceSetMismatch);
        }
        if self.sources.is_empty() {
            return Err(WorkScopeError::EmptyCollection { field: "sources" });
        }
        for source in &self.sources {
            if source.applicable_generation != self.generation {
                return Err(WorkScopeError::SourceSetMismatch);
            }
            if source.assurance.state_fence.resource_generation.value() != scope.generation {
                return Err(WorkScopeError::InvalidSourceEvidence);
            }
            if !privacy.admits(source.assurance.privacy_class) {
                return Err(WorkScopeError::PrivacyDenied);
            }
            if source.assurance.integrity != IntegrityStatus::Verified
                || source.assurance.freshness != FreshnessStatus::Current
                || matches!(source.assurance.quarantine, QuarantineState::Quarantined)
            {
                return Err(WorkScopeError::InvalidSourceEvidence);
            }
        }
        Ok(())
    }
}

/// Stateless onboarding resolver over caller-supplied candidates and sources.
#[derive(Clone, Copy, Debug, Default)]
pub struct OnboardingResolver;

impl OnboardingResolver {
    /// Produces read-only readiness or a typed non-ready outcome.
    #[must_use]
    pub fn resolve(
        &self,
        candidates: &WorkScopeCandidateSet,
        discovery_lease: &DiscoveryReadLease,
        onboarding_lease: &OnboardingLease,
        sources: Option<&GoverningSourceSet>,
        privacy: &PrivacyProfile,
        now: u64,
    ) -> OnboardingOutcome {
        if discovery_lease.validate().is_err()
            || onboarding_lease.validate().is_err()
            || !onboarding_lease.is_active(now)
        {
            return OnboardingOutcome::Degraded(OnboardingDegraded::DiscoveryLeaseExpired);
        }
        let scope = match candidates.resolve() {
            ScopeResolution::Unique(candidate) => candidate,
            ScopeResolution::Ambiguous(set) => return OnboardingOutcome::Ambiguous(set),
            ScopeResolution::NewScope => {
                return OnboardingOutcome::NeedsScope(Box::new(candidates.clone()));
            }
            ScopeResolution::StaleBinding => {
                return OnboardingOutcome::Degraded(OnboardingDegraded::DiscoveryLeaseDenied);
            }
            ScopeResolution::Conflicted => {
                return OnboardingOutcome::Degraded(OnboardingDegraded::InvalidSourceEvidence);
            }
        };
        if scope.scope.lineage_ref.as_deref()
            != Some(onboarding_lease.lineage_candidate_ref.as_str())
            || scope.scope.instance_ref != onboarding_lease.workspace_instance_candidate_ref
        {
            return OnboardingOutcome::Degraded(OnboardingDegraded::DiscoveryLeaseDenied);
        }
        if scope.privacy_class != onboarding_lease.privacy_class
            || !privacy.admits(onboarding_lease.privacy_class)
        {
            return OnboardingOutcome::Degraded(OnboardingDegraded::PrivacyDenied);
        }
        let Some(sources) = sources else {
            return OnboardingOutcome::NeedsSources;
        };
        if sources.generation != onboarding_lease.governing_source_generation {
            return OnboardingOutcome::Degraded(OnboardingDegraded::InvalidSourceEvidence);
        }
        if !privacy.admits(scope.privacy_class) {
            return OnboardingOutcome::Degraded(OnboardingDegraded::PrivacyDenied);
        }
        match sources.validate_for(&scope.scope, privacy) {
            Ok(()) => OnboardingOutcome::ReadyReadOnly {
                scope,
                governing_sources: Box::new(sources.clone()),
                lease_ref: onboarding_lease.lease_ref.clone(),
            },
            Err(WorkScopeError::PrivacyDenied) => {
                OnboardingOutcome::Degraded(OnboardingDegraded::PrivacyDenied)
            }
            Err(WorkScopeError::InvalidSourceEvidence) => {
                OnboardingOutcome::Degraded(OnboardingDegraded::InvalidSourceEvidence)
            }
            Err(_) => OnboardingOutcome::NeedsSources,
        }
    }
}

/// How far a cold-start scope binding has advanced toward authentication.
///
/// `Unbound` is the pre-compile state. [`ColdStartController::compile`] never
/// emits `Unbound`: a unique lease-bound candidate with a missing, exploratory,
/// ambiguous or stale task compiles to `Provisional`, and only an exact
/// current task contract compiles to `Authenticated`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScopeResolutionState {
    Unbound,
    Provisional,
    Authenticated,
    Ambiguous,
}

/// Task selection carried by an [`OnboardingReadinessReceipt`].
///
/// Ambiguous handles are preserved verbatim and never resolved here: the
/// controller has no authority to prefer one candidate over another, so an
/// ambiguous binding always stays non-material until the caller supplies one
/// exact task contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "disposition", content = "detail")]
pub enum TaskBindingState {
    #[serde(rename = "none")]
    None_,
    Exploratory {
        task_ref: String,
        task_revision: u64,
        acceptance_digest: String,
    },
    CurrentTaskContract {
        task_ref: String,
        task_revision: u64,
        acceptance_digest: String,
    },
    Ambiguous {
        candidate_handles: Vec<String>,
    },
    Stale {
        task_ref: String,
        task_revision: u64,
    },
}

/// Cold-start lifecycle position of one compiled readiness receipt.
///
/// `compile` emits a narrow subset: `NeedsTask` for a missing, ambiguous or
/// stale task selection, `ReadyReadOnly` for an exploratory task, and
/// `ReadyMaterial` only for an exact current task contract. `Conflicted` is
/// reserved for conflicted governing sources, which fail compilation instead
/// of producing a receipt; the remaining variants belong to other stages.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadinessLifecycle {
    Unseen,
    Scanning,
    NeedsScope,
    NeedsTask,
    NeedsSources,
    ReadyReadOnly,
    ReadyMaterial,
    Degraded,
    Conflicted,
}

/// Memory assessment carried by an [`OnboardingReadinessReceipt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryState {
    Empty,
    Partial,
    Current,
    Contaminated,
    Unknown,
}

/// Governor-owned cold-start readiness receipt.
///
/// This is the compiled first-useful-work gate: it binds one exact scope,
/// instance and lineage snapshot to one [`StateFence`], one governing-source
/// generation and one task selection. It grants nothing by itself; only a
/// `CurrentTaskContract` binding with `ReadyMaterial` readiness admits
/// material effects, and only through the owning governor path. An
/// `Exploratory` binding compiles to `ReadyReadOnly` and is explicitly
/// non-material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OnboardingReadinessReceipt {
    pub receipt_ref: String,
    pub lease_ref: String,
    pub principal_ref: String,
    pub session_ref: String,
    pub scope: ScopeIdentity,
    pub instance: WorkspaceInstanceIdentity,
    pub lineage: Option<RepositoryLineageIdentity>,
    pub scope_resolution: ScopeResolutionState,
    pub task_binding: TaskBindingState,
    pub state_fence: StateFence,
    pub governing_source_set_ref: String,
    pub governing_source_generation: u64,
    pub governance_profile_ref: String,
    pub limiting_integration_evidence: Vec<String>,
    pub route_profile_ref: String,
    /// Frozen serializer/tokenizer and projection source identities bound at compile time.
    ///
    /// The canonical tokenizer/serializer observation is owned by
    /// eliot-context-contracts `SerializedContextMeasurement`; the receipt
    /// carries the frozen reference values.
    pub serializer_id: String,
    pub serializer_version: String,
    pub serializer_options_digest: String,
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub tokenizer_hash: String,
    pub projection_source_ref: String,
    pub projection_generation: u64,
    pub readiness: ReadinessLifecycle,
    pub memory_state: MemoryState,
    pub missing_inputs: Vec<String>,
    pub next_safe_action: String,
    pub receipt_revision: u64,
}

impl OnboardingReadinessReceipt {
    /// Validates every bound reference without re-resolving any authority.
    ///
    /// # Errors
    ///
    /// Returns an error when any reference is blank, any required revision is
    /// zero, identities disagree, task evidence is incomplete, or a bounded
    /// collection leaves its range (evidence 1..=8, missing inputs 0..=32,
    /// ambiguous handles 2..=16).
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.receipt_ref, "receipt_ref")?;
        text(&self.lease_ref, "lease_ref")?;
        text(&self.principal_ref, "principal_ref")?;
        text(&self.session_ref, "session_ref")?;
        text(&self.governing_source_set_ref, "governing_source_set_ref")?;
        counter(
            self.governing_source_generation,
            "governing_source_generation",
        )?;
        text(&self.governance_profile_ref, "governance_profile_ref")?;
        text(&self.route_profile_ref, "route_profile_ref")?;
        text(&self.serializer_id, "serializer_id")?;
        text(&self.serializer_version, "serializer_version")?;
        text(&self.serializer_options_digest, "serializer_options_digest")?;
        text(&self.tokenizer_id, "tokenizer_id")?;
        text(&self.tokenizer_version, "tokenizer_version")?;
        text(&self.tokenizer_hash, "tokenizer_hash")?;
        text(&self.projection_source_ref, "projection_source_ref")?;
        counter(self.projection_generation, "projection_generation")?;
        text(&self.next_safe_action, "next_safe_action")?;
        counter(self.receipt_revision, "receipt_revision")?;
        self.scope.validate()?;
        self.instance.validate()?;
        if let Some(lineage) = &self.lineage {
            lineage.validate()?;
            if self.scope.lineage_ref.as_deref() != Some(lineage.lineage_ref.as_str()) {
                return Err(WorkScopeError::SourceSetMismatch);
            }
        }
        if self.scope.instance_ref != self.instance.instance_ref
            || self.scope.root_identity != self.instance.root_identity
        {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        self.state_fence
            .validate()
            .map_err(|_| WorkScopeError::InvalidStateFence)?;
        match &self.task_binding {
            TaskBindingState::None_ => Ok(()),
            TaskBindingState::Exploratory {
                task_ref,
                task_revision,
                acceptance_digest,
            }
            | TaskBindingState::CurrentTaskContract {
                task_ref,
                task_revision,
                acceptance_digest,
            } => {
                text(task_ref, "task_ref")?;
                counter(*task_revision, "task_revision")?;
                text(acceptance_digest, "acceptance_digest")
            }
            TaskBindingState::Ambiguous { candidate_handles } => {
                if candidate_handles.len() < 2 || candidate_handles.len() > 16 {
                    return Err(WorkScopeError::EmptyCollection {
                        field: "candidate_handles",
                    });
                }
                unique(candidate_handles.iter(), "candidate_handles")?;
                for handle in candidate_handles {
                    text(handle, "candidate_handles")?;
                }
                Ok(())
            }
            TaskBindingState::Stale {
                task_ref,
                task_revision,
            } => {
                text(task_ref, "task_ref")?;
                counter(*task_revision, "task_revision")
            }
        }?;
        if self.limiting_integration_evidence.is_empty()
            || self.limiting_integration_evidence.len() > 8
        {
            return Err(WorkScopeError::EmptyCollection {
                field: "limiting_integration_evidence",
            });
        }
        for evidence in &self.limiting_integration_evidence {
            text(evidence, "limiting_integration_evidence")?;
        }
        if self.missing_inputs.len() > 32 {
            return Err(WorkScopeError::EmptyCollection {
                field: "missing_inputs",
            });
        }
        for missing in &self.missing_inputs {
            text(missing, "missing_inputs")?;
        }
        Ok(())
    }

    /// Projects the agent- and Human-facing readiness view for this receipt.
    ///
    /// The current readiness state and the smallest missing question travel
    /// with the receipt instead of staying buried in internal setup state: the
    /// first missing input wins, otherwise the readiness lifecycle decides the
    /// question, otherwise there is no missing question. The lease deadline is
    /// carried as the readiness expiry.
    ///
    /// # Errors
    ///
    /// Returns [`WorkScopeError::BindingReceiptMismatch`] when the lease does
    /// not own this receipt.
    pub fn surface(&self, lease: &OnboardingLease) -> Result<ReadinessSurface, WorkScopeError> {
        if lease.lease_ref != self.lease_ref {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        let smallest_missing_question = self.missing_inputs.first().cloned().or_else(|| match self
            .readiness
        {
            ReadinessLifecycle::NeedsScope => Some("scope_disambiguation".to_owned()),
            ReadinessLifecycle::NeedsTask => match &self.task_binding {
                TaskBindingState::Ambiguous { .. } => Some("task_disambiguation".to_owned()),
                TaskBindingState::Stale { .. } => Some("task_refresh".to_owned()),
                TaskBindingState::None_
                | TaskBindingState::Exploratory { .. }
                | TaskBindingState::CurrentTaskContract { .. } => Some("task_ref".to_owned()),
            },
            ReadinessLifecycle::NeedsSources => Some("governing_sources".to_owned()),
            ReadinessLifecycle::Unseen
            | ReadinessLifecycle::Scanning
            | ReadinessLifecycle::Degraded
            | ReadinessLifecycle::Conflicted => Some("readiness_retry".to_owned()),
            ReadinessLifecycle::ReadyReadOnly | ReadinessLifecycle::ReadyMaterial => None,
        });
        Ok(ReadinessSurface {
            lease_ref: self.lease_ref.clone(),
            receipt_ref: self.receipt_ref.clone(),
            readiness: self.readiness,
            smallest_missing_question,
            next_safe_action: self.next_safe_action.clone(),
            lease_deadline: lease.deadline,
        })
    }
}

/// Agent- and Human-facing projection of one compiled readiness receipt.
///
/// This is the smallest inspectable answer a caller needs before attempting
/// scope-sensitive work: the current readiness state, the single smallest
/// missing question (`None` when nothing is missing), the next safe action,
/// and the lease deadline after which the readiness expires.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadinessSurface {
    pub lease_ref: String,
    pub receipt_ref: String,
    pub readiness: ReadinessLifecycle,
    pub smallest_missing_question: Option<String>,
    pub next_safe_action: String,
    pub lease_deadline: u64,
}

/// Caller-selected task input for [`ColdStartController::compile`].
///
/// This is a transient compiler argument, not a persisted binding: ambiguous
/// handles are carried through, never resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskBindingInput {
    NoTask,
    Exploratory {
        task_ref: String,
        task_revision: u64,
        acceptance_digest: String,
    },
    Current {
        task_ref: String,
        task_revision: u64,
        acceptance_digest: String,
    },
    AmbiguousCandidates(Vec<String>),
    Stale {
        task_ref: String,
        task_revision: u64,
    },
}

/// Cold-start trigger enumerated by the onboarding contract.
///
/// Every value routes the discovery pass through the privacy-bounded scanner
/// (`DiscoveryReadLease`): first project open, attach/launch, unknown-workspace
/// event, explicit onboarding request, stale generation, or resume without a
/// current task. No trigger bypasses the discovery lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ColdStartTrigger {
    FirstProjectOpen,
    AttachOrLaunch,
    UnknownWorkspace,
    OnboardingRequest,
    StaleGeneration,
    ResumeWithoutTask,
}

impl ColdStartTrigger {
    /// Returns the deterministic scanner read set for one trigger.
    ///
    /// Stale generations re-check VCS identity (branch/commit/dirty summary)
    /// and governing-source candidates; resumes without a task re-check
    /// identity only and never admit source candidates on their own.
    #[must_use]
    pub fn required_discovery_reads(&self) -> &'static [DiscoveryRead] {
        match self {
            ColdStartTrigger::FirstProjectOpen
            | ColdStartTrigger::AttachOrLaunch
            | ColdStartTrigger::UnknownWorkspace => &[
                DiscoveryRead::FilesystemIdentity,
                DiscoveryRead::VcsIdentity,
                DiscoveryRead::GoverningSourceCandidates,
            ],
            ColdStartTrigger::OnboardingRequest => &[
                DiscoveryRead::FilesystemIdentity,
                DiscoveryRead::GoverningSourceCandidates,
            ],
            ColdStartTrigger::StaleGeneration => &[
                DiscoveryRead::VcsIdentity,
                DiscoveryRead::GoverningSourceCandidates,
            ],
            ColdStartTrigger::ResumeWithoutTask => &[
                DiscoveryRead::FilesystemIdentity,
                DiscoveryRead::VcsIdentity,
            ],
        }
    }
}

/// Stateless cold-start compiler over caller-supplied exact identities.
///
/// `compile` binds one candidate to one lease, source set, fence and task
/// selection and emits an [`OnboardingReadinessReceipt`]. Memory assessment
/// belongs to a later stage, so compilation always emits
/// [`MemoryState::Unknown`] rather than manufacturing a memory claim; likewise
/// the receipt revision is always 1 and advancement is owned elsewhere.
#[derive(Clone, Copy, Debug, Default)]
pub struct ColdStartController;

impl ColdStartController {
    /// Compiles one readiness receipt or fails closed without a fallback.
    ///
    /// # Errors
    ///
    /// Returns [`WorkScopeError::InvalidCounter`] with field `lease` when the
    /// lease is invalid or not active at `now`; [`WorkScopeError::BindingReceiptMismatch`]
    /// when the candidate, the passed identities, or the lease references
    /// disagree; [`WorkScopeError::InvalidStateFence`] when the fence is
    /// invalid and [`WorkScopeError::StateFenceMismatch`] when its resource
    /// generation is stale for the scope or source set;
    /// [`WorkScopeError::PrivacyDenied`] when the candidate class is outside
    /// the privacy boundary; [`WorkScopeError::SourceSetMismatch`] when the
    /// governing sources do not close over the scope; and the usual text,
    /// counter or collection errors when task or receipt fields are invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn compile(
        &self,
        receipt_ref: impl Into<String>,
        lease: &OnboardingLease,
        principal_ref: impl Into<String>,
        session_ref: impl Into<String>,
        scope: &ScopeIdentity,
        instance: &WorkspaceInstanceIdentity,
        lineage: Option<&RepositoryLineageIdentity>,
        candidate: &WorkScopeCandidate,
        sources: &GoverningSourceSet,
        state_fence: &StateFence,
        governance_profile_ref: impl Into<String>,
        limiting_integration_evidence: Vec<String>,
        route_profile_ref: impl Into<String>,
        serializer_id: impl Into<String>,
        serializer_version: impl Into<String>,
        serializer_options_digest: impl Into<String>,
        tokenizer_id: impl Into<String>,
        tokenizer_version: impl Into<String>,
        tokenizer_hash: impl Into<String>,
        projection_source_ref: impl Into<String>,
        projection_generation: u64,
        privacy: &PrivacyProfile,
        task: TaskBindingInput,
        now: u64,
    ) -> Result<OnboardingReadinessReceipt, WorkScopeError> {
        let receipt_ref = receipt_ref.into();
        let principal_ref = principal_ref.into();
        let session_ref = session_ref.into();
        let governance_profile_ref = governance_profile_ref.into();
        let route_profile_ref = route_profile_ref.into();
        let serializer_id = serializer_id.into();
        let serializer_version = serializer_version.into();
        let serializer_options_digest = serializer_options_digest.into();
        let tokenizer_id = tokenizer_id.into();
        let tokenizer_version = tokenizer_version.into();
        let tokenizer_hash = tokenizer_hash.into();
        let projection_source_ref = projection_source_ref.into();
        Self::check_lease_and_identities(lease, scope, instance, lineage, candidate, sources, now)?;
        Self::check_fence_sources_privacy(state_fence, sources, scope, candidate, privacy, lease)?;
        let (task_binding, scope_resolution, readiness, missing_inputs, next_safe_action) =
            Self::resolve_task_binding(task)?;
        let receipt = OnboardingReadinessReceipt {
            receipt_ref,
            lease_ref: lease.lease_ref.clone(),
            principal_ref,
            session_ref,
            scope: scope.clone(),
            instance: instance.clone(),
            lineage: lineage.cloned(),
            scope_resolution,
            task_binding,
            state_fence: state_fence.clone(),
            governing_source_set_ref: format!(
                "governing-source-set:{}:{}",
                sources.scope_ref, sources.generation
            ),
            governing_source_generation: sources.generation,
            governance_profile_ref,
            limiting_integration_evidence,
            route_profile_ref,
            serializer_id,
            serializer_version,
            serializer_options_digest,
            tokenizer_id,
            tokenizer_version,
            tokenizer_hash,
            projection_source_ref,
            projection_generation,
            readiness,
            memory_state: MemoryState::Unknown,
            missing_inputs,
            next_safe_action,
            receipt_revision: 1,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Issues a new receipt revision after invalidation without mutating the
    /// previous receipt value.
    ///
    /// The caller supplies fresh identities for the new lease; the previous
    /// receipt is validated and left untouched, and the new receipt carries
    /// `previous.receipt_revision + 1`.
    ///
    /// # Errors
    ///
    /// Returns the previous receipt's validation error when it is not a
    /// well-formed receipt; [`WorkScopeError::InvalidCounter`] with field
    /// `lease` when neither the lease reference nor the governing-source
    /// generation changed (no new revision is warranted); otherwise the same
    /// errors as [`ColdStartController::compile`].
    #[allow(clippy::too_many_arguments)]
    pub fn recompile(
        &self,
        previous: &OnboardingReadinessReceipt,
        receipt_ref: impl Into<String>,
        lease: &OnboardingLease,
        principal_ref: impl Into<String>,
        session_ref: impl Into<String>,
        scope: &ScopeIdentity,
        instance: &WorkspaceInstanceIdentity,
        lineage: Option<&RepositoryLineageIdentity>,
        candidate: &WorkScopeCandidate,
        sources: &GoverningSourceSet,
        state_fence: &StateFence,
        governance_profile_ref: impl Into<String>,
        limiting_integration_evidence: Vec<String>,
        route_profile_ref: impl Into<String>,
        serializer_id: impl Into<String>,
        serializer_version: impl Into<String>,
        serializer_options_digest: impl Into<String>,
        tokenizer_id: impl Into<String>,
        tokenizer_version: impl Into<String>,
        tokenizer_hash: impl Into<String>,
        projection_source_ref: impl Into<String>,
        projection_generation: u64,
        privacy: &PrivacyProfile,
        task: TaskBindingInput,
        now: u64,
    ) -> Result<OnboardingReadinessReceipt, WorkScopeError> {
        previous.validate()?;
        if lease.lease_ref == previous.lease_ref
            && lease.governing_source_generation == previous.governing_source_generation
        {
            return Err(WorkScopeError::InvalidCounter { field: "lease" });
        }
        let mut receipt = self.compile(
            receipt_ref,
            lease,
            principal_ref,
            session_ref,
            scope,
            instance,
            lineage,
            candidate,
            sources,
            state_fence,
            governance_profile_ref,
            limiting_integration_evidence,
            route_profile_ref,
            serializer_id,
            serializer_version,
            serializer_options_digest,
            tokenizer_id,
            tokenizer_version,
            tokenizer_hash,
            projection_source_ref,
            projection_generation,
            privacy,
            task,
            now,
        )?;
        receipt.receipt_revision = previous.receipt_revision + 1;
        receipt.validate()?;
        Ok(receipt)
    }

    /// Routes one trigger through the privacy-bounded scanner lease.
    ///
    /// # Errors
    ///
    /// Returns [`OnboardingDegraded::DiscoveryLeaseExpired`] when the lease is
    /// invalid or past its deadline, or [`OnboardingDegraded::DiscoveryLeaseDenied`]
    /// when any trigger-required read class is not admitted or exhausted.
    pub fn check_discovery(
        trigger: ColdStartTrigger,
        discovery_lease: &DiscoveryReadLease,
        now: u64,
    ) -> Result<(), OnboardingDegraded> {
        if discovery_lease.validate().is_err() {
            return Err(OnboardingDegraded::DiscoveryLeaseExpired);
        }
        for required in trigger.required_discovery_reads() {
            match discovery_lease.authorize(*required, now) {
                Ok(()) => (),
                Err(DiscoveryLeaseError::Expired) => {
                    return Err(OnboardingDegraded::DiscoveryLeaseExpired);
                }
                Err(
                    DiscoveryLeaseError::ReadNotAdmitted | DiscoveryLeaseError::ConsumptionLimit,
                ) => {
                    return Err(OnboardingDegraded::DiscoveryLeaseDenied);
                }
            }
        }
        Ok(())
    }

    fn check_lease_and_identities(
        lease: &OnboardingLease,
        scope: &ScopeIdentity,
        instance: &WorkspaceInstanceIdentity,
        lineage: Option<&RepositoryLineageIdentity>,
        candidate: &WorkScopeCandidate,
        sources: &GoverningSourceSet,
        now: u64,
    ) -> Result<(), WorkScopeError> {
        lease
            .validate()
            .map_err(|_| WorkScopeError::InvalidCounter { field: "lease" })?;
        if !lease.is_active(now) {
            return Err(WorkScopeError::InvalidCounter { field: "lease" });
        }
        scope.validate()?;
        instance.validate()?;
        if let Some(lineage) = lineage {
            lineage.validate()?;
        }
        if candidate.scope != *scope
            || candidate.instance != *instance
            || candidate.lineage != lineage.cloned()
        {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        if scope.lineage_ref.as_deref() != Some(lease.lineage_candidate_ref.as_str())
            || scope.instance_ref != lease.workspace_instance_candidate_ref
            || lease.governing_source_generation != sources.generation
        {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        if candidate.privacy_class != lease.privacy_class {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        Ok(())
    }

    fn check_fence_sources_privacy(
        state_fence: &StateFence,
        sources: &GoverningSourceSet,
        scope: &ScopeIdentity,
        candidate: &WorkScopeCandidate,
        privacy: &PrivacyProfile,
        lease: &OnboardingLease,
    ) -> Result<(), WorkScopeError> {
        state_fence
            .validate()
            .map_err(|_| WorkScopeError::InvalidStateFence)?;
        if state_fence.resource_generation.value() != scope.generation
            || state_fence.resource_generation.value() != sources.generation
        {
            return Err(WorkScopeError::StateFenceMismatch);
        }
        if !privacy.admits(candidate.privacy_class) {
            return Err(WorkScopeError::PrivacyDenied);
        }
        if !privacy.admits(lease.privacy_class) {
            return Err(WorkScopeError::PrivacyDenied);
        }
        if matches!(
            governance::source_readiness(sources),
            governance::SourceReadiness::Conflicted { .. }
        ) {
            return Err(WorkScopeError::UnresolvedSourceConflict);
        }
        sources
            .validate_for(scope, privacy)
            .map_err(|_| WorkScopeError::SourceSetMismatch)
    }

    fn resolve_task_binding(
        task: TaskBindingInput,
    ) -> Result<
        (
            TaskBindingState,
            ScopeResolutionState,
            ReadinessLifecycle,
            Vec<String>,
            String,
        ),
        WorkScopeError,
    > {
        match task {
            TaskBindingInput::NoTask => Ok((
                TaskBindingState::None_,
                ScopeResolutionState::Provisional,
                ReadinessLifecycle::NeedsTask,
                vec!["task_ref".to_owned()],
                "await_exact_task_binding".to_owned(),
            )),
            TaskBindingInput::Exploratory {
                task_ref,
                task_revision,
                acceptance_digest,
            } => Self::check_task_ref(task_ref, task_revision, acceptance_digest, false),
            TaskBindingInput::Current {
                task_ref,
                task_revision,
                acceptance_digest,
            } => Self::check_task_ref(task_ref, task_revision, acceptance_digest, true),
            TaskBindingInput::AmbiguousCandidates(handles) => {
                Self::check_ambiguous_handles(handles)
            }
            TaskBindingInput::Stale {
                task_ref,
                task_revision,
            } => {
                text(&task_ref, "task_ref")?;
                counter(task_revision, "task_revision")?;
                Ok((
                    TaskBindingState::Stale {
                        task_ref,
                        task_revision,
                    },
                    ScopeResolutionState::Provisional,
                    ReadinessLifecycle::NeedsTask,
                    vec!["task_refresh".to_owned()],
                    "refresh_task_binding".to_owned(),
                ))
            }
        }
    }

    fn check_task_ref(
        task_ref: String,
        task_revision: u64,
        acceptance_digest: String,
        material: bool,
    ) -> Result<
        (
            TaskBindingState,
            ScopeResolutionState,
            ReadinessLifecycle,
            Vec<String>,
            String,
        ),
        WorkScopeError,
    > {
        text(&task_ref, "task_ref")?;
        counter(task_revision, "task_revision")?;
        text(&acceptance_digest, "acceptance_digest")?;
        if material {
            Ok((
                TaskBindingState::CurrentTaskContract {
                    task_ref,
                    task_revision,
                    acceptance_digest,
                },
                ScopeResolutionState::Authenticated,
                ReadinessLifecycle::ReadyMaterial,
                Vec::new(),
                "execute_current_task_contract".to_owned(),
            ))
        } else {
            Ok((
                TaskBindingState::Exploratory {
                    task_ref,
                    task_revision,
                    acceptance_digest,
                },
                ScopeResolutionState::Provisional,
                ReadinessLifecycle::ReadyReadOnly,
                Vec::new(),
                "read_only_governing_sources".to_owned(),
            ))
        }
    }

    fn check_ambiguous_handles(
        handles: Vec<String>,
    ) -> Result<
        (
            TaskBindingState,
            ScopeResolutionState,
            ReadinessLifecycle,
            Vec<String>,
            String,
        ),
        WorkScopeError,
    > {
        if handles.len() < 2 || handles.len() > 16 {
            return Err(WorkScopeError::EmptyCollection {
                field: "candidate_handles",
            });
        }
        unique(handles.iter(), "candidate_handles")?;
        for handle in &handles {
            text(handle, "candidate_handles")?;
        }
        Ok((
            TaskBindingState::Ambiguous {
                candidate_handles: handles,
            },
            ScopeResolutionState::Provisional,
            ReadinessLifecycle::NeedsTask,
            vec!["task_disambiguation".to_owned()],
            "disambiguate_task_candidates".to_owned(),
        ))
    }
}

/// Caller-observed identity key for single-flight join and invalidation.
///
/// Dirty-base evidence arrives as a new governing-source generation: a changed
/// dirty summary that does not advance the reported generation is not
/// observable here, so the producing stage (bootstrap discovery, carrying
/// `GenerationEvidence` with its `dirty_summary_ref` from `identity.rs`) must
/// advance the generation it reports.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OnboardingObservedKey {
    pub lineage_candidate_ref: String,
    pub workspace_instance_candidate_ref: String,
    pub privacy_class: PrivacyClass,
    pub governing_source_generation: u64,
}

impl OnboardingObservedKey {
    /// Validates the observed key without authenticating any authority.
    ///
    /// # Errors
    ///
    /// Returns an error when identity references are blank or the generation
    /// is zero.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.lineage_candidate_ref, "lineage_candidate_ref")?;
        text(
            &self.workspace_instance_candidate_ref,
            "workspace_instance_candidate_ref",
        )?;
        counter(
            self.governing_source_generation,
            "governing_source_generation",
        )
    }

    fn matches_lease(&self, lease: &OnboardingLease) -> bool {
        self.lineage_candidate_ref == lease.lineage_candidate_ref
            && self.workspace_instance_candidate_ref == lease.workspace_instance_candidate_ref
            && self.privacy_class == lease.privacy_class
            && self.governing_source_generation == lease.governing_source_generation
    }
}

/// Outcome of one single-flight attach.
///
/// `Created` and `Joined` carry only the lease reference: participants never
/// create a `WorkScope` or infer a "latest task" on their own. `JoinedTerminal`
/// additionally carries the same terminal [`ReadinessSurface`] every waiter of
/// one lease receives.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "disposition", content = "detail")]
pub enum LeaseJoin {
    Created {
        lease_ref: String,
    },
    Joined {
        lease_ref: String,
    },
    JoinedTerminal {
        lease_ref: String,
        surface: ReadinessSurface,
    },
}

/// Outcome of one readiness invalidation check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "disposition", content = "detail")]
pub enum LeaseInvalidation {
    Current { lease_ref: String },
    Invalidated { lease_ref: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SingleFlightEntry {
    lease: OnboardingLease,
    terminal: Option<OnboardingReadinessReceipt>,
}

/// Caller-owned single-flight registry for concurrent cold-start attaches.
///
/// The registry holds no filesystem, process, credential or store state: it
/// only evaluates caller-supplied leases and receipts. Two attaches that
/// propose the same lease key (exact workspace filesystem/VCS identity plus
/// privacy boundary plus governing-source generation) join the same lease and
/// attach to the same terminal receipt; an attach with a different worktree
/// identity or a changed governing-source generation receives a separate
/// lease. Completed readiness is invalidated rather than mutated: invalidation
/// expires the lease and drops its terminal receipt value, and the replacement
/// readiness arrives as a new receipt revision via
/// [`ColdStartController::recompile`].
#[derive(Clone, Debug, Default)]
pub struct OnboardingSingleFlight {
    entries: Vec<SingleFlightEntry>,
}

impl OnboardingSingleFlight {
    /// Creates an empty single-flight registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Joins a compatible in-flight lease or creates one for a new key.
    ///
    /// # Errors
    ///
    /// Returns [`OnboardingDegraded::DiscoveryLeaseDenied`] when the proposed
    /// lease is invalid, [`OnboardingDegraded::DiscoveryLeaseExpired`] when it
    /// is not active at `now`, or the discovery-lease outcome of
    /// [`ColdStartController::check_discovery`] when the trigger's scanner
    /// pass is not admitted.
    pub fn join(
        &mut self,
        trigger: ColdStartTrigger,
        discovery_lease: &DiscoveryReadLease,
        proposed: OnboardingLease,
        now: u64,
    ) -> Result<LeaseJoin, OnboardingDegraded> {
        if proposed.validate().is_err() {
            return Err(OnboardingDegraded::DiscoveryLeaseDenied);
        }
        if !proposed.is_active(now) {
            return Err(OnboardingDegraded::DiscoveryLeaseExpired);
        }
        ColdStartController::check_discovery(trigger, discovery_lease, now)?;
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.lease.key_matches(&proposed))
        {
            let lease_ref = self.entries[index].lease.lease_ref.clone();
            if let Some(terminal) = self.entries[index].terminal.clone() {
                let surface = terminal
                    .surface(&self.entries[index].lease)
                    .map_err(|_| OnboardingDegraded::DiscoveryLeaseDenied)?;
                return Ok(LeaseJoin::JoinedTerminal { lease_ref, surface });
            }
            if self.entries[index].lease.is_active(now) {
                return Ok(LeaseJoin::Joined { lease_ref });
            }
            let created_ref = proposed.lease_ref.clone();
            self.entries[index] = SingleFlightEntry {
                lease: proposed,
                terminal: None,
            };
            return Ok(LeaseJoin::Created {
                lease_ref: created_ref,
            });
        }
        let created_ref = proposed.lease_ref.clone();
        self.entries.push(SingleFlightEntry {
            lease: proposed,
            terminal: None,
        });
        Ok(LeaseJoin::Created {
            lease_ref: created_ref,
        })
    }

    /// Attaches one terminal receipt to its lease and advances the lease to a
    /// terminal state.
    ///
    /// # Errors
    ///
    /// Returns [`WorkScopeError::InvalidText`] with field `terminal_state`
    /// when the target state is not terminal (`READY`, `AMBIGUOUS`, `FAILED`
    /// or `EXPIRED`); [`WorkScopeError::BindingReceiptMismatch`] when no lease
    /// owns `lease_ref` or the receipt's lease reference or governing-source
    /// generation disagrees with the lease; [`WorkScopeError::InvalidCounter`]
    /// with field `lease` when the lease is no longer active; otherwise the
    /// receipt's own validation error.
    pub fn publish_terminal(
        &mut self,
        lease_ref: &str,
        receipt: OnboardingReadinessReceipt,
        terminal_state: OnboardingLeaseState,
        now: u64,
    ) -> Result<(), WorkScopeError> {
        match terminal_state {
            OnboardingLeaseState::Ready
            | OnboardingLeaseState::Ambiguous
            | OnboardingLeaseState::Failed
            | OnboardingLeaseState::Expired => (),
            OnboardingLeaseState::Discovering
            | OnboardingLeaseState::Resolving
            | OnboardingLeaseState::Compiling => {
                return Err(WorkScopeError::InvalidText {
                    field: "terminal_state",
                });
            }
        }
        receipt.validate()?;
        let index = self
            .entries
            .iter()
            .position(|entry| entry.lease.lease_ref == lease_ref)
            .ok_or(WorkScopeError::BindingReceiptMismatch)?;
        let lease = &self.entries[index].lease;
        if receipt.lease_ref != lease.lease_ref
            || receipt.governing_source_generation != lease.governing_source_generation
        {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        if !lease.is_active(now) {
            return Err(WorkScopeError::InvalidCounter { field: "lease" });
        }
        self.entries[index].lease.state = terminal_state;
        self.entries[index].terminal = Some(receipt);
        Ok(())
    }

    /// Invalidates rather than mutates completed readiness.
    ///
    /// When the observed key (root identity, privacy boundary or
    /// governing-source generation) disagrees with the retained lease, or the
    /// lease is past its deadline at `now`, the lease expires and its terminal
    /// receipt value is dropped untouched; the caller then compiles a new
    /// receipt revision under a new lease.
    ///
    /// # Errors
    ///
    /// Returns the observed key's validation error, or
    /// [`WorkScopeError::BindingReceiptMismatch`] when no lease owns
    /// `lease_ref`.
    pub fn invalidate(
        &mut self,
        lease_ref: &str,
        observed: &OnboardingObservedKey,
        now: u64,
    ) -> Result<LeaseInvalidation, WorkScopeError> {
        observed.validate()?;
        let index = self
            .entries
            .iter()
            .position(|entry| entry.lease.lease_ref == lease_ref)
            .ok_or(WorkScopeError::BindingReceiptMismatch)?;
        if observed.matches_lease(&self.entries[index].lease)
            && self.entries[index].lease.is_active(now)
        {
            return Ok(LeaseInvalidation::Current {
                lease_ref: lease_ref.to_owned(),
            });
        }
        self.entries[index].lease.state = OnboardingLeaseState::Expired;
        self.entries[index].terminal = None;
        Ok(LeaseInvalidation::Invalidated {
            lease_ref: lease_ref.to_owned(),
        })
    }
}

/// ELIOT_ARCH_OWNER: ARCH-SCOPE-01
/// Stateless mid-task scope binding guard.
#[allow(clippy::doc_markdown)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ScopeBindingGuard;

impl ScopeBindingGuard {
    /// Revalidates identity, generation, privacy and governing-source closure.
    #[must_use]
    pub fn check(
        &self,
        expected: &ScopeBinding,
        observed: &ScopeBinding,
        sources: &GoverningSourceSet,
        privacy: &PrivacyProfile,
    ) -> ScopeBindingGuardReceipt {
        let mut disposition = ScopeBindingDisposition::Matched;
        if expected.scope.lineage_ref != observed.scope.lineage_ref
            || expected.scope.instance_ref != observed.scope.instance_ref
            || expected.scope.root_identity != observed.scope.root_identity
        {
            disposition = ScopeBindingDisposition::DifferentInstance;
        } else if expected.scope.scope_ref != observed.scope.scope_ref {
            disposition = ScopeBindingDisposition::Ambiguous;
        } else if expected.scope.generation != observed.scope.generation
            || expected.governing_source_generation != observed.governing_source_generation
        {
            disposition = ScopeBindingDisposition::StaleBinding;
        } else if (expected.privacy_class != observed.privacy_class
            || !privacy.admits(observed.privacy_class))
            || sources.validate_for(&observed.scope, privacy).is_err()
        {
            disposition = ScopeBindingDisposition::Conflicted;
        }
        ScopeBindingGuardReceipt {
            expected_scope_ref: expected.scope.scope_ref.clone(),
            observed_scope_ref: observed.scope.scope_ref.clone(),
            expected_lineage_ref: expected.scope.lineage_ref.clone(),
            observed_lineage_ref: observed.scope.lineage_ref.clone(),
            expected_instance_ref: expected.scope.instance_ref.clone(),
            observed_instance_ref: observed.scope.instance_ref.clone(),
            disposition,
            source_generation: observed.governing_source_generation,
        }
    }
}

impl ScopeBinding {
    /// Validates the retained binding without inferring any external authority.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        self.scope.validate()?;
        counter(
            self.governing_source_generation,
            "governing_source_generation",
        )
    }
}

impl WorkScopeBindingSnapshot {
    /// Constructs a persisted current binding only after full receipt closure.
    pub fn new(
        state_fence: StateFence,
        owner_revision: u64,
        binding: ScopeBinding,
        guard_receipt: ScopeBindingGuardReceipt,
    ) -> Result<Self, WorkScopeError> {
        let snapshot = Self {
            state_fence,
            owner_revision,
            binding,
            guard_receipt,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Validates the complete closed snapshot before construction or recovery.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        self.state_fence
            .validate()
            .map_err(|_| WorkScopeError::InvalidStateFence)?;
        counter(self.owner_revision, "owner_revision")?;
        self.binding.validate()?;
        let receipt = &self.guard_receipt;
        if receipt.disposition != ScopeBindingDisposition::Matched {
            return Err(WorkScopeError::BindingReceiptNotMatched);
        }
        text(&receipt.expected_scope_ref, "expected_scope_ref")?;
        text(&receipt.observed_scope_ref, "observed_scope_ref")?;
        if let Some(lineage) = &receipt.expected_lineage_ref {
            text(lineage, "expected_lineage_ref")?;
        }
        if let Some(lineage) = &receipt.observed_lineage_ref {
            text(lineage, "observed_lineage_ref")?;
        }
        text(&receipt.expected_instance_ref, "expected_instance_ref")?;
        text(&receipt.observed_instance_ref, "observed_instance_ref")?;
        counter(receipt.source_generation, "receipt.source_generation")?;
        let scope = &self.binding.scope;
        if receipt.expected_scope_ref != scope.scope_ref
            || receipt.observed_scope_ref != scope.scope_ref
            || receipt.expected_lineage_ref != scope.lineage_ref
            || receipt.observed_lineage_ref != scope.lineage_ref
            || receipt.expected_instance_ref != scope.instance_ref
            || receipt.observed_instance_ref != scope.instance_ref
            || receipt.source_generation != self.binding.governing_source_generation
        {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkScopeBindingSnapshotWire {
    state_fence: StateFence,
    owner_revision: u64,
    binding: ScopeBinding,
    guard_receipt: ScopeBindingGuardReceipt,
}

impl<'de> Deserialize<'de> for WorkScopeBindingSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = WorkScopeBindingSnapshotWire::deserialize(deserializer)?;
        Self::new(
            wire.state_fence,
            wire.owner_revision,
            wire.binding,
            wire.guard_receipt,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl WorkScopeBindingOwner {
    /// Creates the canonical owner after validating the persisted snapshot.
    pub fn new(snapshot: WorkScopeBindingSnapshot) -> Result<Self, WorkScopeError> {
        snapshot.validate()?;
        Ok(Self { snapshot })
    }

    /// Recovers the owner through the same fail-closed validation path.
    pub fn from_snapshot(snapshot: WorkScopeBindingSnapshot) -> Result<Self, WorkScopeError> {
        Self::new(snapshot)
    }

    /// Reads the current binding only for its exact state fence.
    pub fn read_current(
        &self,
        state_fence: &StateFence,
    ) -> Result<WorkScopeBindingSnapshot, WorkScopeError> {
        state_fence
            .validate()
            .map_err(|_| WorkScopeError::InvalidStateFence)?;
        self.snapshot.validate()?;
        if self.snapshot.state_fence != *state_fence {
            return Err(WorkScopeError::StateFenceMismatch);
        }
        Ok(self.snapshot.clone())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)] // test-only panic-acceptable (#838).
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use serde::de::DeserializeOwned;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn source(privacy_class: PrivacyClass) -> SourceAssurance {
        from_json(serde_json::json!({
            "source_ref": "architecture",
            "provenance_ref": "artifact:architecture",
            "integrity": "VERIFIED",
            "freshness": "CURRENT",
            "competence": "DOMAIN_VERIFIED",
            "independence": "INDEPENDENT",
            "privacy_class": match serde_json::to_value(privacy_class) {
                Ok(value) => value,
                Err(_) => serde_json::Value::String("INTERNAL".into()),
            },
            "instruction_taint": "CLEARED",
            "allowed_epistemic_use": ["OBSERVATION"],
            "allowed_effects": ["READ_ONLY"],
            "required_verifier": null,
            "quarantine": "NONE",
            "state_fence": {
                "authority_epoch": {"lineage_id": TEST_LINEAGE_A, "sequence": 1},
                "resource_generation": 1,
                "task_revision": null,
                "policy_revision": null,
                "integration_revision": null
            }
        }))
    }

    fn from_json<T: DeserializeOwned>(value: serde_json::Value) -> T {
        match serde_json::from_value(value) {
            Ok(value) => value,
            Err(error) => panic!("fixture is invalid: {error}"),
        }
    }

    fn candidate(instance: &str) -> WorkScopeCandidate {
        let scope = ScopeIdentity {
            scope_ref: format!("scope:{instance}"),
            kind: ScopeKind::GitRepo,
            lineage_ref: Some("lineage:one".into()),
            instance_ref: instance.into(),
            root_identity: format!("root:{instance}"),
            generation: 1,
        };
        WorkScopeCandidate {
            instance: WorkspaceInstanceIdentity {
                instance_ref: instance.into(),
                root_identity: format!("root:{instance}"),
                vcs_identity_ref: Some("vcs:one".into()),
                generation: 1,
            },
            scope,
            descriptor_revision: 1,
            lineage: Some(RepositoryLineageIdentity {
                lineage_ref: "lineage:one".into(),
                object_store_ref: "store:one".into(),
                initial_history_ref: "history:one".into(),
                normalized_remote_ref: Some("remote:one".into()),
                manifest_identity_ref: Some("manifest:one".into()),
            }),
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn binding_fixture() -> (StateFence, ScopeBinding, ScopeBindingGuardReceipt) {
        let one = candidate("instance:a");
        let binding = ScopeBinding {
            scope: one.scope.clone(),
            privacy_class: PrivacyClass::Internal,
            governing_source_generation: 1,
        };
        let receipt = ScopeBindingGuard.check(
            &binding,
            &binding,
            &source_set(&one),
            &PrivacyProfile {
                admitted_classes: vec![PrivacyClass::Internal],
            },
        );
        (
            StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::genesis()),
            binding,
            receipt,
        )
    }

    fn source_set(scope: &WorkScopeCandidate) -> GoverningSourceSet {
        match GoverningSourceSet::new(
            scope.scope.scope_ref.clone(),
            scope.scope.generation,
            vec![GoverningSource {
                source_ref: "architecture".into(),
                role: GoverningSourceRole::Architecture,
                assurance: source(PrivacyClass::Internal),
                applicable_generation: 1,
                status: SourceStatus::Admitted,
                domains: Vec::new(),
                digest: "a".repeat(64),
                authority_basis: None,
            }],
            Vec::new(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("source fixture is invalid: {error}"),
        }
    }

    fn lease() -> DiscoveryReadLease {
        DiscoveryReadLease {
            lease_ref: "lease:one".into(),
            proposer_ref: "proposer:one".into(),
            session_ref: "session:one".into(),
            host_ref: "host:one".into(),
            root_filesystem_identity_ref: "fs:one".into(),
            candidate_root_ref: "root:a".into(),
            allowed_reads: vec![DiscoveryRead::FilesystemIdentity],
            deadline: 10,
            consumption_limit: 1,
            consumed: 0,
        }
    }

    fn onboarding_lease() -> OnboardingLease {
        OnboardingLease {
            lease_ref: "onboarding:one".into(),
            lineage_candidate_ref: "lineage:one".into(),
            workspace_instance_candidate_ref: "instance:a".into(),
            privacy_class: PrivacyClass::Internal,
            governing_source_generation: 1,
            compiler_epoch: 1,
            state: OnboardingLeaseState::Compiling,
            deadline: 10,
        }
    }

    #[test]
    fn same_lineage_different_instances_remains_ambiguous() {
        let set = match WorkScopeCandidateSet::new(
            "root:observed",
            vec![candidate("instance:a"), candidate("instance:b")],
            CandidateDisposition::Ambiguous,
            Some("question:which-root".into()),
        ) {
            Ok(value) => value,
            Err(error) => panic!("candidate fixture is invalid: {error}"),
        };
        assert!(matches!(set.resolve(), ScopeResolution::Ambiguous(_)));
    }

    #[test]
    fn candidate_normalization_is_independent_of_input_permutation() {
        let first = candidate("instance:a");
        let second = candidate("instance:b");
        let left = match WorkScopeCandidateSet::new(
            "root:observed",
            vec![first.clone(), second.clone()],
            CandidateDisposition::Ambiguous,
            None,
        ) {
            Ok(value) => value,
            Err(error) => panic!("candidate fixture is invalid: {error}"),
        };
        let right = match WorkScopeCandidateSet::new(
            "root:observed",
            vec![second, first],
            CandidateDisposition::Ambiguous,
            None,
        ) {
            Ok(value) => value,
            Err(error) => panic!("candidate fixture is invalid: {error}"),
        };
        assert_eq!(left.candidates, right.candidates);
    }

    #[test]
    fn privacy_boundary_degrades_without_fallback() {
        let one = candidate("instance:a");
        let set = match WorkScopeCandidateSet::new(
            "root:a",
            vec![one.clone()],
            CandidateDisposition::Unique,
            None,
        ) {
            Ok(value) => value,
            Err(error) => panic!("candidate fixture is invalid: {error}"),
        };
        let outcome = OnboardingResolver.resolve(
            &set,
            &lease(),
            &onboarding_lease(),
            Some(&source_set(&one)),
            &PrivacyProfile {
                admitted_classes: vec![PrivacyClass::Public],
            },
            1,
        );
        assert_eq!(
            outcome,
            OnboardingOutcome::Degraded(OnboardingDegraded::PrivacyDenied)
        );
    }

    #[test]
    fn source_order_is_canonical_and_lease_is_bounded() {
        let one = candidate("instance:a");
        let mut lease = lease();
        assert!(
            lease
                .authorize(DiscoveryRead::FilesystemIdentity, 10)
                .is_ok()
        );
        assert_eq!(
            lease.authorize(DiscoveryRead::VcsIdentity, 1),
            Err(DiscoveryLeaseError::ReadNotAdmitted)
        );
        lease.consumed = 1;
        assert_eq!(
            lease.authorize(DiscoveryRead::FilesystemIdentity, 1),
            Err(DiscoveryLeaseError::ConsumptionLimit)
        );
        assert_eq!(source_set(&one).sources[0].source_ref, "architecture");
    }

    #[test]
    fn binding_guard_requires_exact_instance_and_generation() {
        let one = candidate("instance:a");
        let sources = source_set(&one);
        let expected = ScopeBinding {
            scope: one.scope.clone(),
            privacy_class: PrivacyClass::Internal,
            governing_source_generation: 1,
        };
        let mut observed = expected.clone();
        observed.scope.instance_ref = "instance:b".into();
        let receipt = ScopeBindingGuard.check(
            &expected,
            &observed,
            &sources,
            &PrivacyProfile {
                admitted_classes: vec![PrivacyClass::Internal],
            },
        );
        assert_eq!(
            receipt.disposition,
            ScopeBindingDisposition::DifferentInstance
        );
    }

    #[test]
    fn current_binding_owner_constructs_recovers_and_reads_a_clone() {
        let (state_fence, binding, receipt) = binding_fixture();
        let snapshot = match WorkScopeBindingSnapshot::new(state_fence.clone(), 7, binding, receipt)
        {
            Ok(value) => value,
            Err(error) => panic!("binding snapshot fixture is invalid: {error}"),
        };
        let owner = match WorkScopeBindingOwner::new(snapshot.clone()) {
            Ok(value) => value,
            Err(error) => panic!("binding owner fixture is invalid: {error}"),
        };
        let mut read = match owner.read_current(&state_fence) {
            Ok(value) => value,
            Err(error) => panic!("current binding read failed: {error}"),
        };
        assert_eq!(read, snapshot);
        read.owner_revision = 8;
        assert_eq!(
            owner
                .read_current(&state_fence)
                .map(|value| value.owner_revision),
            Ok(7)
        );

        let encoded = match serde_json::to_value(&snapshot) {
            Ok(value) => value,
            Err(error) => panic!("binding snapshot serialization failed: {error}"),
        };
        let recovered_snapshot: WorkScopeBindingSnapshot = from_json(encoded.clone());
        assert_eq!(recovered_snapshot, snapshot);
        let recovered_owner = match WorkScopeBindingOwner::from_snapshot(recovered_snapshot) {
            Ok(value) => value,
            Err(error) => panic!("binding owner recovery failed: {error}"),
        };
        assert_eq!(recovered_owner.read_current(&state_fence), Ok(snapshot));
    }

    #[test]
    fn current_binding_owner_rejects_stale_fence_and_zero_revision() {
        let (expected_fence, binding, receipt) = binding_fixture();
        let snapshot = match WorkScopeBindingSnapshot::new(
            expected_fence.clone(),
            1,
            binding.clone(),
            receipt.clone(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("binding snapshot fixture is invalid: {error}"),
        };
        let owner = match WorkScopeBindingOwner::new(snapshot) {
            Ok(value) => value,
            Err(error) => panic!("binding owner fixture is invalid: {error}"),
        };
        let stale_fence = StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(2).unwrap_or(ResourceGeneration::genesis()),
        );
        assert_eq!(
            owner.read_current(&stale_fence),
            Err(WorkScopeError::StateFenceMismatch)
        );
        assert_eq!(
            WorkScopeBindingSnapshot::new(expected_fence, 0, binding, receipt),
            Err(WorkScopeError::InvalidCounter {
                field: "owner_revision"
            })
        );
    }

    #[test]
    fn current_binding_owner_rejects_non_matched_receipts() {
        let (state_fence, binding, mut receipt) = binding_fixture();
        receipt.disposition = ScopeBindingDisposition::DifferentInstance;
        assert_eq!(
            WorkScopeBindingSnapshot::new(state_fence, 1, binding, receipt),
            Err(WorkScopeError::BindingReceiptNotMatched)
        );
    }

    #[test]
    fn current_binding_owner_rejects_receipt_identity_drift() {
        let (state_fence, binding, receipt) = binding_fixture();
        let mut cases = Vec::new();

        let mut scope_ref = receipt.clone();
        scope_ref.expected_scope_ref = "scope:other".into();
        cases.push(scope_ref);
        let mut lineage = receipt.clone();
        lineage.observed_lineage_ref = Some("lineage:other".into());
        cases.push(lineage);
        let mut instance = receipt.clone();
        instance.expected_instance_ref = "instance:other".into();
        cases.push(instance);
        let mut generation = receipt;
        generation.source_generation = 2;
        cases.push(generation);

        for drifted_receipt in cases {
            assert_eq!(
                WorkScopeBindingSnapshot::new(
                    state_fence.clone(),
                    1,
                    binding.clone(),
                    drifted_receipt,
                ),
                Err(WorkScopeError::BindingReceiptMismatch)
            );
        }
    }

    #[test]
    fn snapshot_deserialization_rejects_non_matched_receipt() {
        let (state_fence, binding, mut receipt) = binding_fixture();
        receipt.disposition = ScopeBindingDisposition::Conflicted;
        let invalid = serde_json::json!({
            "state_fence": state_fence,
            "owner_revision": 1,
            "binding": binding,
            "guard_receipt": receipt,
        });
        assert!(serde_json::from_value::<WorkScopeBindingSnapshot>(invalid).is_err());
    }

    fn readiness_fence() -> StateFence {
        StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::genesis())
    }

    fn compile_with(
        candidate: &WorkScopeCandidate,
        instance: &WorkspaceInstanceIdentity,
        fence: &StateFence,
        task: TaskBindingInput,
    ) -> Result<OnboardingReadinessReceipt, WorkScopeError> {
        let lease = onboarding_lease();
        let sources = source_set(candidate);
        let privacy = PrivacyProfile {
            admitted_classes: vec![PrivacyClass::Internal],
        };
        ColdStartController.compile(
            "receipt:one",
            &lease,
            "principal:test",
            "session:test",
            &candidate.scope,
            instance,
            candidate.lineage.as_ref(),
            candidate,
            &sources,
            fence,
            "governance-profile:test",
            vec!["integration:evidence:one".into()],
            "route-profile:test",
            "serializer:test",
            "serializer-version:test",
            "serializer-options:test",
            "tokenizer:test",
            "tokenizer-version:test",
            "tokenizer-hash:test",
            "projection-source:test",
            1,
            &privacy,
            task,
            1,
        )
    }

    fn current_task_input() -> TaskBindingInput {
        TaskBindingInput::Current {
            task_ref: "task:one".into(),
            task_revision: 1,
            acceptance_digest: "digest:acceptance:one".into(),
        }
    }

    #[test]
    fn unique_current_task_compiles_to_ready_material() {
        let one = candidate("instance:a");
        let receipt = match compile_with(
            &one,
            &one.instance,
            &readiness_fence(),
            current_task_input(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("readiness compilation failed: {error}"),
        };
        assert_eq!(receipt.readiness, ReadinessLifecycle::ReadyMaterial);
        assert_eq!(receipt.scope, one.scope);
        assert_eq!(receipt.instance, one.instance);
        assert_eq!(receipt.lineage, one.lineage);
        assert_eq!(
            receipt.scope_resolution,
            ScopeResolutionState::Authenticated
        );
        assert!(matches!(
            receipt.task_binding,
            TaskBindingState::CurrentTaskContract { .. }
        ));
        match receipt.validate() {
            Ok(()) => (),
            Err(error) => panic!("compiled receipt is invalid: {error}"),
        }
    }

    #[test]
    fn ambiguous_candidates_preserve_handles_without_selecting_task() {
        let one = candidate("instance:a");
        let handles = vec!["task:a".to_owned(), "task:b".to_owned()];
        let receipt = match compile_with(
            &one,
            &one.instance,
            &readiness_fence(),
            TaskBindingInput::AmbiguousCandidates(handles.clone()),
        ) {
            Ok(value) => value,
            Err(error) => panic!("readiness compilation failed: {error}"),
        };
        assert_eq!(
            receipt.task_binding,
            TaskBindingState::Ambiguous {
                candidate_handles: handles,
            }
        );
        assert_ne!(receipt.readiness, ReadinessLifecycle::ReadyMaterial);
    }

    #[test]
    fn missing_task_compiles_to_needs_task() {
        let one = candidate("instance:a");
        let receipt = match compile_with(
            &one,
            &one.instance,
            &readiness_fence(),
            TaskBindingInput::NoTask,
        ) {
            Ok(value) => value,
            Err(error) => panic!("readiness compilation failed: {error}"),
        };
        assert_eq!(receipt.task_binding, TaskBindingState::None_);
        assert_eq!(receipt.readiness, ReadinessLifecycle::NeedsTask);
    }

    #[test]
    fn stale_fence_generation_is_rejected() {
        let one = candidate("instance:a");
        let stale = StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            match ResourceGeneration::new(2) {
                Ok(value) => value,
                Err(error) => panic!("fence fixture is invalid: {error}"),
            },
        );
        assert_eq!(
            compile_with(&one, &one.instance, &stale, current_task_input()),
            Err(WorkScopeError::StateFenceMismatch)
        );
    }

    #[test]
    fn changed_instance_is_rejected() {
        let one = candidate("instance:a");
        let other = candidate("instance:b");
        assert_eq!(
            compile_with(
                &one,
                &other.instance,
                &readiness_fence(),
                current_task_input()
            ),
            Err(WorkScopeError::BindingReceiptMismatch)
        );
    }

    #[test]
    fn exploratory_task_is_read_only_and_never_material() {
        let one = candidate("instance:a");
        let receipt = match compile_with(
            &one,
            &one.instance,
            &readiness_fence(),
            TaskBindingInput::Exploratory {
                task_ref: "task:explore".into(),
                task_revision: 1,
                acceptance_digest: "digest:acceptance:explore".into(),
            },
        ) {
            Ok(value) => value,
            Err(error) => panic!("readiness compilation failed: {error}"),
        };
        assert_eq!(receipt.readiness, ReadinessLifecycle::ReadyReadOnly);
        assert_ne!(receipt.readiness, ReadinessLifecycle::ReadyMaterial);
        assert!(matches!(
            receipt.task_binding,
            TaskBindingState::Exploratory { .. }
        ));
    }

    fn bootstrap_evidence() -> BootstrapScanEvidence {
        BootstrapScanEvidence {
            canonical_root_ref: "root:a".into(),
            filesystem_identity_ref: "root:a".into(),
            vcs_branch_ref: None,
            vcs_commit_ref: None,
            vcs_dirty_summary_ref: None,
            file_distribution: Vec::new(),
            manifests: Vec::new(),
            build_profiles: Vec::new(),
            root_services: Vec::new(),
            editor_workspaces: Vec::new(),
            existing_records: Vec::new(),
            adapters: Vec::new(),
            recent_changes: Vec::new(),
            artifact_dirs: Vec::new(),
            execution_identity: None,
            broker_attached: None,
            redacted_literal_identities: Vec::new(),
            unresolved_fields: Vec::new(),
            attested_reads: vec![DiscoveryRead::FilesystemIdentity],
        }
    }

    fn bootstrap_key() -> DiscoveryLeaseKey {
        DiscoveryLeaseKey {
            proposer_ref: "proposer:one".into(),
            session_ref: "session:one".into(),
            host_ref: "host:one".into(),
            root_filesystem_identity_ref: "root:a".into(),
        }
    }

    fn bootstrap_lease() -> DiscoveryReadLease {
        match issue_discovery_lease(&DiscoveryLeaseRequest {
            proposer_ref: "proposer:one".into(),
            session_ref: "session:one".into(),
            host_ref: "host:one".into(),
            candidate_root_ref: "root:a".into(),
            root_filesystem_identity_ref: "root:a".into(),
            allowed_reads: vec![DiscoveryRead::FilesystemIdentity],
            consumption_limit: 4,
            deadline: 10,
        }) {
            Ok(value) => value,
            Err(error) => panic!("lease fixture is invalid: {error}"),
        }
    }

    fn bootstrap_observed() -> ObservedScopeResources {
        ObservedScopeResources {
            kind: ScopeKind::GitRepo,
            display_name: "root-a".into(),
            lineage: None,
            instances: vec![WorkspaceInstanceIdentity {
                instance_ref: "instance:a".into(),
                root_identity: "root:a".into(),
                vcs_identity_ref: None,
                generation: 1,
            }],
            canonical_resource_refs: Vec::new(),
            external_resource_refs: Vec::new(),
            root_identities: vec!["root:a".into()],
            generation: GenerationEvidence {
                branch_ref: None,
                commit_ref: None,
                dirty_summary_ref: None,
                task_revision: None,
                resource_generation: match ResourceGeneration::new(1) {
                    Ok(value) => value,
                    Err(error) => panic!("generation fixture is invalid: {error}"),
                },
            },
            supporting_evidence: Vec::new(),
        }
    }

    fn bootstrap_policy() -> DescriptorPolicy {
        DescriptorPolicy {
            owner_refs: vec!["owner:one".into()],
            truth_surface_refs: Vec::new(),
            verifier_refs: vec!["verifier:one".into()],
            privacy: PrivacyProfile {
                admitted_classes: vec![PrivacyClass::Internal],
            },
            authority_profile_ref: None,
            execution_identity: ResourceExecutionIdentity::InteractiveUser {
                sid_ref: "sid:one".into(),
            },
            available_capabilities: Vec::new(),
            missing_capabilities: Vec::new(),
        }
    }

    fn bootstrap_discovery(privacy_boundary: Option<PrivacyBoundary>) -> BootstrapDiscoveryInputs {
        BootstrapDiscoveryInputs {
            scan_ref: "scan:one".into(),
            candidate_privacy: PrivacyClass::Internal,
            privacy_boundary,
            observed: bootstrap_observed(),
            policy: bootstrap_policy(),
            evidence: bootstrap_evidence(),
            proposed_kind: ScopeKind::GitRepo,
            identity_fingerprint: "fingerprint:one".into(),
            governing_source_refs: Vec::new(),
            now: 1,
        }
    }

    struct TestReceiptStore {
        stored: Vec<ScanDisclosureReceipt>,
    }

    impl ScanDisclosureStore for TestReceiptStore {
        fn store_receipt(
            &mut self,
            receipt: &ScanDisclosureReceipt,
        ) -> Result<ScanReceiptHandle, WorkScopeError> {
            receipt.validate()?;
            self.stored.push(receipt.clone());
            Ok(ScanReceiptHandle {
                receipt_ref: receipt.scan_ref.clone(),
                store_ref: format!("durable:{}", self.stored.len()),
            })
        }
    }

    fn bootstrap_boundary() -> PrivacyBoundary {
        PrivacyBoundary {
            boundary_ref: "boundary:one".into(),
            admitted_classes: vec![PrivacyClass::Internal],
            lineage: None,
        }
    }

    #[test]
    fn a1_valid_lease_bootstrap_returns_profile_and_receipt_with_allowed_classes_only() {
        let mut lease = bootstrap_lease();
        let mut store = TestReceiptStore { stored: Vec::new() };
        let outcome = match run_bootstrap_discovery(
            &mut store,
            &mut lease,
            &bootstrap_key(),
            &bootstrap_discovery(Some(bootstrap_boundary())),
        ) {
            Ok(value) => value,
            Err(error) => panic!("valid-lease bootstrap failed: {error}"),
        };
        let (profile, receipt, persisted) = match outcome {
            BootstrapScanOutcome::Completed {
                profile,
                receipt,
                persisted,
                resolver_inputs: _,
            } => (profile, receipt, persisted),
            BootstrapScanOutcome::PrivacyBoundaryRequired { code, .. } => {
                panic!("valid-lease bootstrap demanded a boundary: {code}")
            }
        };
        assert_eq!(receipt.allowed, vec![DiscoveryRead::FilesystemIdentity]);
        assert!(receipt.omitted.contains(&ForbiddenScanClass::CommandLines));
        assert!(receipt.omitted.contains(&ForbiddenScanClass::RecentOutput));
        assert!(
            receipt
                .omitted
                .contains(&ForbiddenScanClass::NeighboringRoots)
        );
        assert!(
            receipt
                .omitted
                .contains(&ForbiddenScanClass::SecretLiterals)
        );
        assert!(receipt.redacted.is_empty());
        assert_eq!(receipt.lease_ref, lease.lease_ref);
        assert_eq!(receipt.candidate_root_ref, "root:a");
        assert_eq!(profile.roots, vec!["root:a".to_owned()]);
        assert_eq!(lease.consumed, 1);
        assert_eq!(profile.verifier_candidates, vec!["verifier:one".to_owned()]);
        assert_eq!(persisted.receipt_ref, receipt.scan_ref);
        assert!(!persisted.store_ref.trim().is_empty());
        assert_eq!(store.stored.len(), 1);
        assert_eq!(store.stored[0], *receipt);
    }

    #[test]
    fn a2_missing_boundary_returns_boundary_required_with_question_only() {
        let mut lease = bootstrap_lease();
        let mut store = TestReceiptStore { stored: Vec::new() };
        let outcome = match run_bootstrap_discovery(
            &mut store,
            &mut lease,
            &bootstrap_key(),
            &bootstrap_discovery(None),
        ) {
            Ok(value) => value,
            Err(error) => panic!("boundary-less scan failed: {error}"),
        };
        let (code, question) = match outcome {
            BootstrapScanOutcome::PrivacyBoundaryRequired {
                code,
                discriminative_question,
            } => (code, discriminative_question),
            BootstrapScanOutcome::Completed { .. } => {
                panic!("boundary-less scan persisted a profile")
            }
        };
        assert_eq!(code, SCAN_PRIVACY_BOUNDARY_REQUIRED);
        assert!(!question.trim().is_empty());
        assert_eq!(lease.consumed, 0);
        assert!(store.stored.is_empty());
    }
}
