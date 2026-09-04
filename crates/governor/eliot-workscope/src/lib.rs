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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkScopeCandidate {
    pub scope: ScopeIdentity,
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryReadLease {
    pub lease_ref: String,
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OnboardingLease {
    pub lease_ref: String,
    pub lineage_candidate_ref: String,
    pub workspace_instance_candidate_ref: String,
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoverningSource {
    pub source_ref: String,
    pub role: GoverningSourceRole,
    pub assurance: SourceAssurance,
    pub applicable_generation: u64,
    pub status: SourceStatus,
    pub domains: Vec<ObservationDomainRef>,
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

/// `ELIOT_ARCH_OWNER`: `ARCH-SCOPE-01`
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
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
    use serde::de::DeserializeOwned;

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
                "authority_epoch": 1,
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
            StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
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
            AuthorityEpoch::genesis(),
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
}
