//! Deterministic privacy-bounded bootstrap discovery (issue #1788).
//!
//! The scanner is a model-free fast pass over caller-supplied observations: it
//! performs no IO, inspects no filesystem, process, credential, or store, and
//! mints no scope authority. It validates a [`DiscoveryReadLease`] issued for
//! one proposer/session/host and one candidate-root filesystem identity,
//! enforces the lease allowlist (charging one consumption unit per collected
//! allowed class and rejecting every forbidden operation), applies the
//! privacy-before-capture boundary from I4.3.1, persists a
//! [`ScanDisclosureReceipt`] of allowed/omitted/redacted/unresolved fields,
//! and emits a [`ProvisionalScopeProfile`]. Only scanner evidence and bounded
//! source-candidate references flow into [`WorkScopeResolver`]; discovery never
//! confers scope authority (no session/task/token tier is ever populated).

use super::{
    DiscoveryLeaseError, DiscoveryRead, DiscoveryReadLease, GoverningSourceRole,
    HostObservedHandles, ManifestBoundaryClaim, RepositoryLineageIdentity, ResolutionOutcome,
    ResolutionRequest, ResourceExecutionIdentity, ScopeKind, WorkScopeCandidateSet, WorkScopeError,
    WorkScopeResolver, counter, text, unique,
};
use eliot_security_contracts::PrivacyClass;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Agent-facing code returned when no applicable privacy boundary exists.
///
/// The scanner offers only a non-persisted discriminative question alongside
/// this code; nothing about the candidate root is persisted on this path.
pub const SCAN_PRIVACY_BOUNDARY_REQUIRED: &str = "SCAN_PRIVACY_BOUNDARY_REQUIRED";

/// Maximum consumption units any single discovery lease may grant.
pub const MAX_DISCOVERY_CONSUMPTION: u32 = 64;

/// Operations a discovery lease never admits while it is active (I4.2 `forbidden`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryOperation {
    ProjectMemoryAdmission,
    Mutation,
    CredentialRead,
    BroadNeighborScan,
    ExternalModelDelivery,
}

/// Field classes the scanner excludes by default (I4.3.1 scan boundary).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ForbiddenScanClass {
    CommandLines,
    RecentOutput,
    NeighboringRoots,
    SecretLiterals,
}

/// Onboarding depth recommended by a completed scan (I4.3 output).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingRecommendation {
    None_,
    Shallow,
    Normal,
    Deep,
}

/// Caller-supplied request to issue a discovery lease.
///
/// The key binding is established here: the issued lease reference is derived
/// deterministically from proposer, session, host, and root filesystem
/// identity, and [`DiscoveryReadLease::key_matches`] re-derives it for
/// verification. Allowed reads are a non-empty subset of the five admitted
/// classes; the forbidden operations need no representation because no input
/// can admit them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryLeaseRequest {
    pub proposer_ref: String,
    pub session_ref: String,
    pub host_ref: String,
    pub candidate_root_ref: String,
    pub root_filesystem_identity_ref: String,
    pub allowed_reads: Vec<DiscoveryRead>,
    pub consumption_limit: u32,
    pub deadline: u64,
}

impl DiscoveryLeaseRequest {
    /// Validates the key binding and the bounded lease shape.
    ///
    /// # Errors
    ///
    /// Returns an error when any identity reference is blank, no read class is
    /// admitted, a read class is duplicated, the consumption limit is outside
    /// `1..=MAX_DISCOVERY_CONSUMPTION`, or the deadline is zero.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.proposer_ref, "proposer_ref")?;
        text(&self.session_ref, "session_ref")?;
        text(&self.host_ref, "host_ref")?;
        text(&self.candidate_root_ref, "candidate_root_ref")?;
        text(
            &self.root_filesystem_identity_ref,
            "root_filesystem_identity_ref",
        )?;
        if self.allowed_reads.is_empty() {
            return Err(WorkScopeError::EmptyCollection {
                field: "allowed_reads",
            });
        }
        unique(self.allowed_reads.iter(), "allowed_reads")?;
        if self.consumption_limit == 0 || self.consumption_limit > MAX_DISCOVERY_CONSUMPTION {
            return Err(WorkScopeError::InvalidCounter {
                field: "consumption_limit",
            });
        }
        counter(self.deadline, "deadline")
    }
}

/// Derives the lease reference from the lease key identities.
#[must_use]
pub fn derive_lease_ref(
    proposer_ref: &str,
    session_ref: &str,
    host_ref: &str,
    root_filesystem_identity_ref: &str,
) -> String {
    format!(
        "discovery-lease:{proposer_ref}:{session_ref}:{host_ref}:{root_filesystem_identity_ref}"
    )
}

/// Issues an expiring, consumption-limited discovery lease for one key.
///
/// The lease starts unconsumed; collection charges it through
/// [`DiscoveryReadLease::charge`].
///
/// # Errors
///
/// Returns an error when the request is malformed (see
/// [`DiscoveryLeaseRequest::validate`]).
pub fn issue_discovery_lease(
    request: &DiscoveryLeaseRequest,
) -> Result<DiscoveryReadLease, WorkScopeError> {
    request.validate()?;
    Ok(DiscoveryReadLease {
        lease_ref: derive_lease_ref(
            &request.proposer_ref,
            &request.session_ref,
            &request.host_ref,
            &request.root_filesystem_identity_ref,
        ),
        candidate_root_ref: request.candidate_root_ref.clone(),
        allowed_reads: request.allowed_reads.clone(),
        deadline: request.deadline,
        consumption_limit: request.consumption_limit,
        consumed: 0,
    })
}

impl DiscoveryReadLease {
    /// Verifies the lease was issued for this proposer/session/host and root
    /// filesystem identity by re-deriving its reference.
    #[must_use]
    pub fn key_matches(
        &self,
        proposer_ref: &str,
        session_ref: &str,
        host_ref: &str,
        root_filesystem_identity_ref: &str,
    ) -> bool {
        self.lease_ref
            == derive_lease_ref(
                proposer_ref,
                session_ref,
                host_ref,
                root_filesystem_identity_ref,
            )
    }

    /// Authorizes one allowed read and charges one consumption unit.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the deadline, consumption limit, or admitted
    /// read set rejects the request; the lease is unchanged on failure.
    pub fn charge(
        &mut self,
        requested: DiscoveryRead,
        now: u64,
    ) -> Result<(), DiscoveryLeaseError> {
        self.authorize(requested, now)?;
        self.consumed = self.consumed.saturating_add(1);
        Ok(())
    }
}

/// Rejects a forbidden operation under an active discovery lease.
///
/// A lease never admits project-memory admission, mutation, credential reads,
/// broad neighboring-root scans, or external-model delivery: the rejection is
/// unconditional and typed so callers map it without string matching.
///
/// # Errors
///
/// Always returns [`DiscoveryLeaseError::ReadNotAdmitted`].
pub fn authorize_operation(_operation: DiscoveryOperation) -> Result<(), DiscoveryLeaseError> {
    Err(DiscoveryLeaseError::ReadNotAdmitted)
}

/// File-type distribution bucket: kind label plus deterministic count.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileTypeCount {
    pub kind: String,
    pub count: u64,
}

/// Manifest identity: reference plus name hash only, never file content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestEvidence {
    pub manifest_ref: String,
    pub name_hash: String,
}

/// Known build/test command from a registered profile: profile identity only,
/// never an observed command line.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisteredBuildProfile {
    pub profile_ref: String,
    pub kind: String,
}

/// Root-associated process/service metadata: identity only, no command lines.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootServiceEvidence {
    pub service_ref: String,
    pub kind: String,
}

/// Open editor/workspace metadata: identity only, no editor state content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EditorWorkspaceEvidence {
    pub editor_ref: String,
    pub workspace_ref: String,
}

/// Existing ELIOT record association: reference plus record kind.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExistingRecordEvidence {
    pub record_ref: String,
    pub kind: String,
}

/// Available adapter candidacy: reference plus adapter kind.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdapterEvidence {
    pub adapter_ref: String,
    pub kind: String,
}

/// Recent filesystem change: non-reversible path identity plus change kind.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummary {
    pub path_identity_hash: String,
    pub change_kind: String,
    pub observed_at: u64,
}

/// Known artifact/output directory: non-reversible identity plus kind.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDirEvidence {
    pub dir_identity_hash: String,
    pub kind: String,
}

/// Caller-supplied bootstrap-scan observations for one candidate root.
///
/// Every field is optional metadata in an allowed class. The struct has no
/// command-line, terminal-output, neighboring-root, or secret-literal fields:
/// excluded material cannot be submitted, only omitted (recorded on the
/// receipt). Secret and high-risk literals appear solely as non-reversible
/// identity references in `redacted_literal_identities`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapScanEvidence {
    pub canonical_root_ref: String,
    pub filesystem_identity_ref: String,
    pub vcs_branch_ref: Option<String>,
    pub vcs_commit_ref: Option<String>,
    pub vcs_dirty_summary_ref: Option<String>,
    pub file_distribution: Vec<FileTypeCount>,
    pub manifests: Vec<ManifestEvidence>,
    pub build_profiles: Vec<RegisteredBuildProfile>,
    pub root_services: Vec<RootServiceEvidence>,
    pub editor_workspaces: Vec<EditorWorkspaceEvidence>,
    pub existing_records: Vec<ExistingRecordEvidence>,
    pub adapters: Vec<AdapterEvidence>,
    pub recent_changes: Vec<ChangeSummary>,
    pub artifact_dirs: Vec<ArtifactDirEvidence>,
    pub execution_identity: Option<ResourceExecutionIdentity>,
    pub broker_attached: Option<bool>,
    pub redacted_literal_identities: Vec<String>,
    pub unresolved_fields: Vec<DiscoveryRead>,
}

impl BootstrapScanEvidence {
    /// Validates bounded, well-formed observations without interpreting them.
    ///
    /// # Errors
    ///
    /// Returns an error when identity references are blank, a bounded
    /// collection leaves its range (file distribution/manifests/profiles/
    /// services/editors/records/adapters 0..=32, changes/artifacts/redacted
    /// 0..=128, unresolved 0..=16), or a reference is blank or duplicated.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.canonical_root_ref, "canonical_root_ref")?;
        text(&self.filesystem_identity_ref, "filesystem_identity_ref")?;
        if let Some(branch) = &self.vcs_branch_ref {
            text(branch, "vcs_branch_ref")?;
        }
        if let Some(commit) = &self.vcs_commit_ref {
            text(commit, "vcs_commit_ref")?;
        }
        if let Some(dirty) = &self.vcs_dirty_summary_ref {
            text(dirty, "vcs_dirty_summary_ref")?;
        }
        Self::check_bounded(self.file_distribution.len(), 32, "file_distribution")?;
        for entry in &self.file_distribution {
            text(&entry.kind, "file_distribution.kind")?;
        }
        Self::check_bounded(self.manifests.len(), 32, "manifests")?;
        for manifest in &self.manifests {
            text(&manifest.manifest_ref, "manifests.manifest_ref")?;
            text(&manifest.name_hash, "manifests.name_hash")?;
        }
        unique(
            self.manifests.iter().map(|item| &item.manifest_ref),
            "manifests.manifest_ref",
        )?;
        Self::check_bounded(self.build_profiles.len(), 32, "build_profiles")?;
        for profile in &self.build_profiles {
            text(&profile.profile_ref, "build_profiles.profile_ref")?;
            text(&profile.kind, "build_profiles.kind")?;
        }
        Self::check_bounded(self.root_services.len(), 32, "root_services")?;
        for service in &self.root_services {
            text(&service.service_ref, "root_services.service_ref")?;
            text(&service.kind, "root_services.kind")?;
        }
        Self::check_bounded(self.editor_workspaces.len(), 32, "editor_workspaces")?;
        for editor in &self.editor_workspaces {
            text(&editor.editor_ref, "editor_workspaces.editor_ref")?;
            text(&editor.workspace_ref, "editor_workspaces.workspace_ref")?;
        }
        Self::check_bounded(self.existing_records.len(), 32, "existing_records")?;
        for record in &self.existing_records {
            text(&record.record_ref, "existing_records.record_ref")?;
            text(&record.kind, "existing_records.kind")?;
        }
        Self::check_bounded(self.adapters.len(), 32, "adapters")?;
        for adapter in &self.adapters {
            text(&adapter.adapter_ref, "adapters.adapter_ref")?;
            text(&adapter.kind, "adapters.kind")?;
        }
        Self::check_bounded(self.recent_changes.len(), 128, "recent_changes")?;
        for change in &self.recent_changes {
            text(
                &change.path_identity_hash,
                "recent_changes.path_identity_hash",
            )?;
            text(&change.change_kind, "recent_changes.change_kind")?;
            counter(change.observed_at, "recent_changes.observed_at")?;
        }
        Self::check_bounded(self.artifact_dirs.len(), 128, "artifact_dirs")?;
        for dir in &self.artifact_dirs {
            text(&dir.dir_identity_hash, "artifact_dirs.dir_identity_hash")?;
            text(&dir.kind, "artifact_dirs.kind")?;
        }
        if let Some(ResourceExecutionIdentity::InteractiveUser { sid_ref }) =
            &self.execution_identity
        {
            text(sid_ref, "execution_identity.sid_ref")?;
        }
        Self::check_bounded(
            self.redacted_literal_identities.len(),
            128,
            "redacted_literal_identities",
        )?;
        for identity in &self.redacted_literal_identities {
            text(identity, "redacted_literal_identities")?;
        }
        unique(
            self.redacted_literal_identities.iter(),
            "redacted_literal_identities",
        )?;
        Self::check_bounded(self.unresolved_fields.len(), 16, "unresolved_fields")?;
        unique(self.unresolved_fields.iter(), "unresolved_fields")?;
        Ok(())
    }

    fn check_bounded(len: usize, max: usize, field: &'static str) -> Result<(), WorkScopeError> {
        if len > max {
            return Err(WorkScopeError::EmptyCollection { field });
        }
        Ok(())
    }
}

/// Durable record of what one scan was allowed, omitted, redacted, and left
/// unresolved (I4.3.1). Omitted classes are always the four default-excluded
/// classes; nothing excluded ever reaches durable capture.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanDisclosureReceipt {
    pub scan_ref: String,
    pub lease_ref: String,
    pub candidate_root_ref: String,
    pub allowed: Vec<DiscoveryRead>,
    pub omitted: Vec<ForbiddenScanClass>,
    pub redacted: Vec<String>,
    pub unresolved: Vec<DiscoveryRead>,
    pub privacy_boundary_ref: Option<String>,
}

impl ScanDisclosureReceipt {
    /// Validates the receipt shape without re-running the scan.
    ///
    /// # Errors
    ///
    /// Returns an error when references are blank, allowed/unresolved classes
    /// are duplicated, redacted identities are blank or duplicated, or the
    /// omitted set does not cover every default-excluded class.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.scan_ref, "scan_ref")?;
        text(&self.lease_ref, "lease_ref")?;
        text(&self.candidate_root_ref, "candidate_root_ref")?;
        unique(self.allowed.iter(), "allowed")?;
        unique(self.unresolved.iter(), "unresolved")?;
        for identity in &self.redacted {
            text(identity, "redacted")?;
        }
        unique(self.redacted.iter(), "redacted")?;
        for required in [
            ForbiddenScanClass::CommandLines,
            ForbiddenScanClass::RecentOutput,
            ForbiddenScanClass::NeighboringRoots,
            ForbiddenScanClass::SecretLiterals,
        ] {
            if !self.omitted.contains(&required) {
                return Err(WorkScopeError::EmptyCollection { field: "omitted" });
            }
        }
        if let Some(boundary) = &self.privacy_boundary_ref {
            text(boundary, "privacy_boundary_ref")?;
        }
        Ok(())
    }
}

/// Deterministic pre-scope profile emitted by a completed scan (I4.3 output).
///
/// All values derive from caller-supplied scan evidence without a model call.
/// The profile proposes candidates and gaps; it authenticates nothing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvisionalScopeProfile {
    pub proposed_kind: ScopeKind,
    pub identity_fingerprint: String,
    pub roots: Vec<String>,
    pub project_units: Vec<String>,
    pub likely_languages: Vec<String>,
    pub active_resources: Vec<String>,
    pub truth_surfaces_available: Vec<String>,
    pub verifier_candidates: Vec<String>,
    pub adapter_candidates: Vec<String>,
    pub capability_gaps: Vec<String>,
    pub confidence: u8,
    pub onboarding_recommendation: OnboardingRecommendation,
    pub scan_evidence_refs: Vec<String>,
}

impl ProvisionalScopeProfile {
    /// Validates the profile shape without re-running the scan.
    ///
    /// # Errors
    ///
    /// Returns an error when references are blank or duplicated, no evidence
    /// reference is carried, confidence exceeds 100, or a bounded collection
    /// leaves its range (roots/project units/languages/resources/surfaces/
    /// verifiers/adapters/gaps 0..=32, evidence refs 1..=64).
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.identity_fingerprint, "identity_fingerprint")?;
        Self::check_bounded(self.roots.len(), 32, "roots")?;
        for root in &self.roots {
            text(root, "roots")?;
        }
        unique(self.roots.iter(), "roots")?;
        Self::check_bounded(self.project_units.len(), 32, "project_units")?;
        for unit in &self.project_units {
            text(unit, "project_units")?;
        }
        Self::check_list(&self.likely_languages, 32, "likely_languages")?;
        Self::check_list(&self.active_resources, 32, "active_resources")?;
        Self::check_list(
            &self.truth_surfaces_available,
            32,
            "truth_surfaces_available",
        )?;
        Self::check_list(&self.verifier_candidates, 32, "verifier_candidates")?;
        Self::check_list(&self.adapter_candidates, 32, "adapter_candidates")?;
        Self::check_list(&self.capability_gaps, 32, "capability_gaps")?;
        if self.confidence > 100 {
            return Err(WorkScopeError::InvalidCounter {
                field: "confidence",
            });
        }
        if self.scan_evidence_refs.is_empty() || self.scan_evidence_refs.len() > 64 {
            return Err(WorkScopeError::EmptyCollection {
                field: "scan_evidence_refs",
            });
        }
        for evidence in &self.scan_evidence_refs {
            text(evidence, "scan_evidence_refs")?;
        }
        unique(self.scan_evidence_refs.iter(), "scan_evidence_refs")?;
        Ok(())
    }

    fn check_bounded(len: usize, max: usize, field: &'static str) -> Result<(), WorkScopeError> {
        if len > max {
            return Err(WorkScopeError::EmptyCollection { field });
        }
        Ok(())
    }

    fn check_list(
        values: &[String],
        max: usize,
        field: &'static str,
    ) -> Result<(), WorkScopeError> {
        Self::check_bounded(values.len(), max, field)?;
        for value in values {
            text(value, field)?;
        }
        unique(values.iter(), field)?;
        Ok(())
    }
}

/// Bounded resolver inputs derived from scan evidence only.
///
/// Only the evidence tiers are populated: host handles (exact root/VCS
/// identity), lineage, and manifest boundary. Session/task, binding-token, and
/// registered tiers stay `None`, so filesystem discovery can never confer
/// scope authority. Bounded governing-source candidates travel as opaque
/// source references alongside the request; their content is never admitted
/// here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScannerResolverInputs {
    pub host_handles: Option<HostObservedHandles>,
    pub lineage: Option<RepositoryLineageIdentity>,
    pub manifest_boundary: Option<ManifestBoundaryClaim>,
    pub governing_source_refs: Vec<String>,
}

impl ScannerResolverInputs {
    /// Validates present tiers and bounded source references.
    ///
    /// # Errors
    ///
    /// Returns an error when present tier evidence is malformed, a source
    /// reference is blank or duplicated, or more than 32 source references
    /// are carried.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        if let Some(handles) = &self.host_handles {
            handles.validate()?;
        }
        if let Some(lineage) = &self.lineage {
            lineage.validate()?;
        }
        if let Some(boundary) = &self.manifest_boundary {
            boundary.validate()?;
        }
        if self.governing_source_refs.len() > 32 {
            return Err(WorkScopeError::EmptyCollection {
                field: "governing_source_refs",
            });
        }
        for source in &self.governing_source_refs {
            text(source, "governing_source_refs")?;
        }
        unique(self.governing_source_refs.iter(), "governing_source_refs")?;
        Ok(())
    }

    /// Builds the resolver request: scanner evidence tiers plus the preserved
    /// candidate set, and nothing else.
    ///
    /// # Errors
    ///
    /// Returns an error when the scanner inputs are malformed.
    pub fn to_resolution_request(
        &self,
        candidates: &WorkScopeCandidateSet,
    ) -> Result<ResolutionRequest, WorkScopeError> {
        self.validate()?;
        Ok(ResolutionRequest {
            candidates: candidates.clone(),
            session_task: None,
            binding_token: None,
            resumed_task: None,
            host_handles: self.host_handles.clone(),
            registered: None,
            lineage: self.lineage.clone(),
            manifest_boundary: self.manifest_boundary.clone(),
        })
    }
}

/// What one deterministic bootstrap scan produced.
///
/// `Completed` carries the profile, the disclosure receipt, and the bounded
/// resolver inputs. `PrivacyBoundaryRequired` carries the agent-facing code
/// and a non-persisted discriminative question; nothing is persisted on that
/// path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "disposition", content = "detail")]
pub enum BootstrapScanOutcome {
    Completed {
        profile: Box<ProvisionalScopeProfile>,
        receipt: Box<ScanDisclosureReceipt>,
        resolver_inputs: Box<ScannerResolverInputs>,
    },
    PrivacyBoundaryRequired {
        code: String,
        discriminative_question: String,
    },
}

/// Deterministic model-free bootstrap scanner over caller-supplied evidence.
#[derive(Clone, Copy, Debug, Default)]
pub struct BootstrapScanner;

impl BootstrapScanner {
    /// Runs one privacy-bounded scan against the lease and boundary.
    ///
    /// The lease must authorize every collected allowed class; one consumption
    /// unit is charged per collected class. The privacy boundary must admit
    /// `candidate_privacy`; otherwise the outcome is `PrivacyBoundaryRequired`
    /// with only a non-persisted discriminative question. Forbidden operations
    /// stay rejected, excluded classes stay omitted, and secret material
    /// persists only as the caller-supplied non-reversible identities.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryLeaseError`] when the lease is expired, exhausted,
    /// or does not admit a collected class, and [`WorkScopeError`] when scan
    /// references or evidence are malformed.
    #[allow(
        clippy::too_many_arguments,
        reason = "scan joins lease, boundary, evidence, and profile inputs in one deterministic constructor"
    )]
    pub fn scan(
        scan_ref: impl Into<String>,
        lease: &mut DiscoveryReadLease,
        candidate_privacy: PrivacyClass,
        privacy_boundary: Option<&PrivacyBoundary>,
        evidence: &BootstrapScanEvidence,
        proposed_kind: ScopeKind,
        identity_fingerprint: impl Into<String>,
        governing_source_refs: Vec<String>,
        now: u64,
    ) -> Result<BootstrapScanOutcome, WorkScopeError> {
        let scan_ref = scan_ref.into();
        let identity_fingerprint = identity_fingerprint.into();
        text(&scan_ref, "scan_ref")?;
        text(&identity_fingerprint, "identity_fingerprint")?;
        lease
            .validate()
            .map_err(|_| WorkScopeError::InvalidCounter { field: "lease" })?;
        evidence.validate()?;
        let Some(boundary) = privacy_boundary else {
            return Ok(BootstrapScanOutcome::PrivacyBoundaryRequired {
                code: SCAN_PRIVACY_BOUNDARY_REQUIRED.to_owned(),
                discriminative_question: discriminative_question(&evidence.canonical_root_ref)?,
            });
        };
        boundary.validate()?;
        if !boundary.admits(candidate_privacy) {
            return Ok(BootstrapScanOutcome::PrivacyBoundaryRequired {
                code: SCAN_PRIVACY_BOUNDARY_REQUIRED.to_owned(),
                discriminative_question: discriminative_question(&evidence.canonical_root_ref)?,
            });
        }
        if evidence.filesystem_identity_ref != lease.candidate_root_ref
            && evidence.canonical_root_ref != lease.candidate_root_ref
        {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        let collected = collected_classes(evidence);
        for class in &collected {
            lease
                .charge(*class, now)
                .map_err(|_| WorkScopeError::InvalidCounter { field: "lease" })?;
        }
        let inputs = ScannerResolverInputs {
            host_handles: host_handles_for(evidence),
            lineage: boundary.lineage.clone(),
            manifest_boundary: manifest_boundary_for(evidence),
            governing_source_refs,
        };
        inputs.validate()?;
        let receipt = ScanDisclosureReceipt {
            scan_ref: scan_ref.clone(),
            lease_ref: lease.lease_ref.clone(),
            candidate_root_ref: lease.candidate_root_ref.clone(),
            allowed: collected.clone(),
            omitted: vec![
                ForbiddenScanClass::CommandLines,
                ForbiddenScanClass::RecentOutput,
                ForbiddenScanClass::NeighboringRoots,
                ForbiddenScanClass::SecretLiterals,
            ],
            redacted: evidence.redacted_literal_identities.clone(),
            unresolved: evidence.unresolved_fields.clone(),
            privacy_boundary_ref: Some(boundary.boundary_ref.clone()),
        };
        receipt.validate()?;
        let profile = Self::profile_for(
            &scan_ref,
            proposed_kind,
            identity_fingerprint,
            evidence,
            &collected,
        )?;
        Ok(BootstrapScanOutcome::Completed {
            profile: Box::new(profile),
            receipt: Box::new(receipt),
            resolver_inputs: Box::new(inputs),
        })
    }

    /// Resolves scanner-derived inputs through the evidence-first resolver.
    ///
    /// Discovery evidence populates only the host-handles, lineage, and
    /// manifest-boundary tiers, so resolution can distinguish candidates but
    /// never authenticates a scope; owner issuance stays separate.
    ///
    /// # Errors
    ///
    /// Returns an error when the scanner inputs or candidate set are malformed.
    /// Malformed input fails; it never falls through to a weaker tier.
    pub fn resolve_with_scan(
        inputs: &ScannerResolverInputs,
        candidates: &WorkScopeCandidateSet,
    ) -> Result<ResolutionOutcome, WorkScopeError> {
        WorkScopeResolver::resolve(&inputs.to_resolution_request(candidates)?)
    }

    fn profile_for(
        scan_ref: &str,
        proposed_kind: ScopeKind,
        identity_fingerprint: String,
        evidence: &BootstrapScanEvidence,
        collected: &[DiscoveryRead],
    ) -> Result<ProvisionalScopeProfile, WorkScopeError> {
        let mut evidence_refs = vec![format!("scan:{scan_ref}")];
        for class in collected {
            evidence_refs.push(format!("scan:{scan_ref}:{}", read_label(*class)));
        }
        let project_units: Vec<String> = evidence
            .manifests
            .iter()
            .map(|manifest| manifest.manifest_ref.clone())
            .collect();
        let likely_languages: Vec<String> = evidence
            .file_distribution
            .iter()
            .map(|entry| entry.kind.clone())
            .collect();
        let mut active_resources: Vec<String> = evidence
            .root_services
            .iter()
            .map(|service| service.service_ref.clone())
            .collect();
        active_resources.extend(
            evidence
                .editor_workspaces
                .iter()
                .map(|editor| editor.workspace_ref.clone()),
        );
        active_resources.sort();
        active_resources.dedup();
        let truth_surfaces_available: Vec<String> = evidence
            .existing_records
            .iter()
            .map(|record| record.record_ref.clone())
            .collect();
        let adapter_candidates: Vec<String> = evidence
            .adapters
            .iter()
            .map(|adapter| adapter.adapter_ref.clone())
            .collect();
        let mut capability_gaps = Vec::new();
        if evidence.execution_identity.is_none() {
            capability_gaps.push("execution_identity".to_owned());
        }
        if evidence.broker_attached != Some(true) {
            capability_gaps.push("user_broker".to_owned());
        }
        if evidence.build_profiles.is_empty() {
            capability_gaps.push("build_profiles".to_owned());
        }
        if evidence.adapters.is_empty() {
            capability_gaps.push("adapters".to_owned());
        }
        if !evidence.unresolved_fields.is_empty() {
            capability_gaps.push("unresolved_evidence".to_owned());
        }
        let confidence = match collected.len() {
            0 => 0,
            1 => 20,
            2 => 40,
            3 => 60,
            4 => 80,
            _ => 100,
        };
        let onboarding_recommendation = match (capability_gaps.len(), evidence.manifests.len()) {
            (0, _) => OnboardingRecommendation::Normal,
            (_, 0) => OnboardingRecommendation::None_,
            (1..=2, _) => OnboardingRecommendation::Shallow,
            _ => OnboardingRecommendation::Deep,
        };
        let profile = ProvisionalScopeProfile {
            proposed_kind,
            identity_fingerprint,
            roots: vec![evidence.canonical_root_ref.clone()],
            project_units,
            likely_languages,
            active_resources,
            truth_surfaces_available,
            verifier_candidates: Vec::new(),
            adapter_candidates,
            capability_gaps,
            confidence,
            onboarding_recommendation,
            scan_evidence_refs: evidence_refs,
        };
        profile.validate()?;
        Ok(profile)
    }
}

/// Privacy boundary admitted for one scan: the privacy profile plus the
/// lineage evidence the resolver may consume as a bounded candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivacyBoundary {
    pub boundary_ref: String,
    pub admitted_classes: Vec<PrivacyClass>,
    pub lineage: Option<RepositoryLineageIdentity>,
}

impl PrivacyBoundary {
    /// Validates the boundary shape.
    ///
    /// # Errors
    ///
    /// Returns an error when the boundary reference is blank, no class is
    /// admitted, a class is duplicated, or the lineage evidence is malformed.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.boundary_ref, "boundary_ref")?;
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
        if let Some(lineage) = &self.lineage {
            lineage.validate()?;
        }
        Ok(())
    }

    /// Returns whether the candidate class is inside this boundary.
    #[must_use]
    pub fn admits(&self, class: PrivacyClass) -> bool {
        self.admitted_classes.contains(&class)
    }
}

/// Names the governing-source roles a scan may surface as bounded candidates.
///
/// Roles are fixed by the source model; the scanner passes references only and
/// never admits source content.
#[must_use]
pub fn candidate_source_roles() -> Vec<GoverningSourceRole> {
    vec![
        GoverningSourceRole::Architecture,
        GoverningSourceRole::Implementation,
        GoverningSourceRole::BuildTestContract,
        GoverningSourceRole::DomainPolicy,
    ]
}

fn discriminative_question(canonical_root_ref: &str) -> Result<String, WorkScopeError> {
    text(canonical_root_ref, "canonical_root_ref")?;
    Ok(format!(
        "which privacy boundary authorizes discovery for {canonical_root_ref}?"
    ))
}

fn read_label(class: DiscoveryRead) -> &'static str {
    match class {
        DiscoveryRead::FilesystemIdentity => "filesystem_identity",
        DiscoveryRead::VcsIdentity => "vcs_identity",
        DiscoveryRead::ManifestNamesAndHashes => "manifest_names_and_hashes",
        DiscoveryRead::KnownFormatHeaders => "known_format_headers",
        DiscoveryRead::GoverningSourceCandidates => "governing_source_candidates",
    }
}

fn collected_classes(evidence: &BootstrapScanEvidence) -> Vec<DiscoveryRead> {
    let mut collected = vec![DiscoveryRead::FilesystemIdentity];
    if evidence.vcs_branch_ref.is_some()
        || evidence.vcs_commit_ref.is_some()
        || evidence.vcs_dirty_summary_ref.is_some()
    {
        collected.push(DiscoveryRead::VcsIdentity);
    }
    if !evidence.manifests.is_empty() || !evidence.build_profiles.is_empty() {
        collected.push(DiscoveryRead::ManifestNamesAndHashes);
    }
    if !evidence.file_distribution.is_empty()
        || !evidence.recent_changes.is_empty()
        || !evidence.artifact_dirs.is_empty()
    {
        collected.push(DiscoveryRead::KnownFormatHeaders);
    }
    if !evidence.existing_records.is_empty() || !evidence.adapters.is_empty() {
        collected.push(DiscoveryRead::GoverningSourceCandidates);
    }
    collected
}

fn host_handles_for(evidence: &BootstrapScanEvidence) -> Option<HostObservedHandles> {
    let vcs_identity_ref = evidence
        .vcs_commit_ref
        .clone()
        .or_else(|| evidence.vcs_branch_ref.clone());
    if evidence.canonical_root_ref.trim().is_empty() {
        return None;
    }
    Some(HostObservedHandles {
        observed_root_ref: evidence.canonical_root_ref.clone(),
        vcs_identity_ref,
        open_file_refs: Vec::new(),
        resource_refs: Vec::new(),
    })
}

fn manifest_boundary_for(evidence: &BootstrapScanEvidence) -> Option<ManifestBoundaryClaim> {
    evidence
        .manifests
        .first()
        .map(|manifest| ManifestBoundaryClaim {
            manifest_ref: manifest.manifest_ref.clone(),
            root_ref: evidence.canonical_root_ref.clone(),
        })
}
