//! Deterministic privacy-bounded bootstrap discovery (issue #1788).
//!
//! The scanner is a model-free fast pass over caller-supplied observations:
//! it performs no IO of its own. Identity and metadata enter only as typed
//! caller evidence that the production caller
//! ([`run_bootstrap_discovery`]) binds to live [`ObservedScopeResources`]
//! before the scan runs: the candidate root and filesystem identity must name
//! observed resources, VCS references must equal the observed generation, and
//! every populated evidence group must be attested by the caller as a
//! lease-admitted read class. Unattested or unobserved material fails closed;
//! excluded classes (command lines, recent output, neighboring roots, raw
//! secret/high-risk literals) have no intake field at all, so they cannot be
//! submitted, only omitted (recorded on the receipt). Secret and high-risk
//! literals cross the boundary solely as non-reversible digest identities
//! enforced by shape, never copied as opaque caller strings.
//!
//! The scanner validates a [`DiscoveryReadLease`] issued for one
//! proposer/session/host and one candidate-root filesystem identity, verifies
//! the lease key binding by re-deriving its reference
//! ([`DiscoveryReadLease::key_matches`]) before any charge, runs the
//! forbidden-operation guard ([`authorize_operation`]) on every scan,
//! enforces the lease allowlist (charging one consumption unit per collected
//! allowed class and rejecting every forbidden operation), applies the
//! privacy-before-capture boundary from I4.3.1, durably writes the
//! [`ScanDisclosureReceipt`] of allowed/omitted/redacted/unresolved fields
//! through a [`ScanDisclosureStore`] before reporting completion, and emits a
//! [`ProvisionalScopeProfile`] whose verifier candidates come from the
//! owner's registered verifier references. Only scanner evidence and bounded
//! source-candidate references flow into [`WorkScopeResolver`]; discovery never
//! confers scope authority (no session/task/token tier is ever populated).

use super::{
    DescriptorPolicy, DiscoveryLeaseError, DiscoveryRead, DiscoveryReadLease, GoverningSourceRole,
    HostObservedHandles, ManifestBoundaryClaim, ObservedScopeResources, RepositoryLineageIdentity,
    ResolutionOutcome, ResolutionRequest, ResourceExecutionIdentity, ScopeKind,
    WorkScopeCandidateSet, WorkScopeError, WorkScopeResolver, counter, digest, text, unique,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
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

/// Key a discovery lease is bound to: one proposer/session/host and one
/// candidate-root filesystem identity.
///
/// The key is presented at every scan alongside the lease; the scanner
/// re-derives the lease reference from it and rejects the scan without
/// consumption when the lease was not issued for this key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryLeaseKey {
    pub proposer_ref: String,
    pub session_ref: String,
    pub host_ref: String,
    pub root_filesystem_identity_ref: String,
}

impl DiscoveryLeaseKey {
    /// Validates the key shape without issuing or charging anything.
    ///
    /// # Errors
    ///
    /// Returns an error when any key identity reference is blank.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.proposer_ref, "lease_key.proposer_ref")?;
        text(&self.session_ref, "lease_key.session_ref")?;
        text(&self.host_ref, "lease_key.host_ref")?;
        text(
            &self.root_filesystem_identity_ref,
            "lease_key.root_filesystem_identity_ref",
        )
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
/// The issued lease retains the full key components alongside the derived
/// reference, so every later use re-verifies the binding through
/// [`DiscoveryReadLease::key_matches`]. The lease starts unconsumed;
/// collection charges it through [`DiscoveryReadLease::charge`].
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
        proposer_ref: request.proposer_ref.clone(),
        session_ref: request.session_ref.clone(),
        host_ref: request.host_ref.clone(),
        root_filesystem_identity_ref: request.root_filesystem_identity_ref.clone(),
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
/// unconditional and typed so callers map it without string matching. The
/// scanner invokes this guard for every forbidden operation on every scan
/// through [`deny_forbidden_operations`]; it is never an uncalled helper.
///
/// # Errors
///
/// Always returns [`DiscoveryLeaseError::ReadNotAdmitted`].
pub fn authorize_operation(_operation: DiscoveryOperation) -> Result<(), DiscoveryLeaseError> {
    Err(DiscoveryLeaseError::ReadNotAdmitted)
}

/// Runs the forbidden-operation guard for one scan.
///
/// Every [`DiscoveryOperation`] must be rejected by [`authorize_operation`];
/// a guard that ever admits an operation fails the scan closed instead of
/// charging the lease. Scans that reach the charging step have therefore
/// passed an explicit forbidden-operation denial, not merely an allowlist
/// check.
///
/// # Errors
///
/// Returns [`WorkScopeError::BindingReceiptMismatch`] when the guard admits
/// any forbidden operation.
fn deny_forbidden_operations() -> Result<(), WorkScopeError> {
    for operation in [
        DiscoveryOperation::ProjectMemoryAdmission,
        DiscoveryOperation::Mutation,
        DiscoveryOperation::CredentialRead,
        DiscoveryOperation::BroadNeighborScan,
        DiscoveryOperation::ExternalModelDelivery,
    ] {
        if authorize_operation(operation).is_ok() {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
    }
    Ok(())
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
/// digest identities in `redacted_literal_identities`; each entry must be a
/// 64-character lowercase hex digest, so opaque caller strings are rejected
/// at intake instead of being copied onto the receipt.
///
/// `attested_reads` is the caller's typed attestation of which allowed-class
/// reads produced this evidence. The scanner requires the attested set to
/// equal the populated-field set exactly: unattested populated fields and
/// attested-but-empty classes both fail the scan closed before any charge.
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
    pub attested_reads: Vec<DiscoveryRead>,
}

impl BootstrapScanEvidence {
    /// Validates bounded, well-formed observations without interpreting them.
    ///
    /// Redaction identities must already be non-reversible digests: arbitrary
    /// caller strings are rejected here, so the receipt can never carry an
    /// unredacted literal the caller relabeled as an identity.
    ///
    /// # Errors
    ///
    /// Returns an error when identity references are blank, a bounded
    /// collection leaves its range (file distribution/manifests/profiles/
    /// services/editors/records/adapters 0..=32, changes/artifacts/redacted
    /// 0..=128, unresolved 0..=16, attested reads 1..=5), a reference is blank
    /// or duplicated, a redaction identity is not a digest, or no read class
    /// is attested.
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
            digest(identity, "redacted_literal_identities")?;
        }
        unique(
            self.redacted_literal_identities.iter(),
            "redacted_literal_identities",
        )?;
        Self::check_bounded(self.unresolved_fields.len(), 16, "unresolved_fields")?;
        unique(self.unresolved_fields.iter(), "unresolved_fields")?;
        if self.attested_reads.is_empty() || self.attested_reads.len() > 5 {
            return Err(WorkScopeError::EmptyCollection {
                field: "attested_reads",
            });
        }
        unique(self.attested_reads.iter(), "attested_reads")?;
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
/// classes; nothing excluded ever reaches durable capture. Redacted entries
/// are non-reversible digests enforced at intake and re-checked here, so a
/// receipt can never durably carry a raw literal.
///
/// A receipt value alone is not persistence: [`BootstrapScanner::scan`]
/// writes the receipt through a [`ScanDisclosureStore`] and reports
/// completion only with the resulting [`ScanReceiptHandle`].
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
    /// are duplicated, redacted identities are blank, duplicated, or not
    /// non-reversible digests, or the omitted set does not cover every
    /// default-excluded class.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.scan_ref, "scan_ref")?;
        text(&self.lease_ref, "lease_ref")?;
        text(&self.candidate_root_ref, "candidate_root_ref")?;
        unique(self.allowed.iter(), "allowed")?;
        unique(self.unresolved.iter(), "unresolved")?;
        for identity in &self.redacted {
            digest(identity, "redacted")?;
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

/// Versioned schema of the owner-bound scan disclosure write identity.
///
/// A changed privacy boundary, governing-source generation, root identity or
/// scanner schema creates a new receipt under a new identity; historical
/// evidence stays addressable under retention policy and is never mutated.
pub const SCAN_DISCLOSURE_SCHEMA_VERSION: u32 = 1;

/// Domain separator for scan disclosure operation identities (I5.27).
pub const SCAN_DISCLOSURE_OPERATION_DOMAIN: &str = "eliot.scan-disclosure.v1";

/// Filename prefix of the retired loose-file captures. A matching filename
/// alone is never owner provenance: pre-created files are quarantined through
/// [`quarantine_loose_scan_disclosure`] and never adopted as receipts.
pub const LOOSE_SCAN_DISCLOSURE_PREFIX: &str = "scan-disclosure-";
/// Filename suffix of the retired loose-file captures.
pub const LOOSE_SCAN_DISCLOSURE_SUFFIX: &str = ".json";

/// Owner-issued storage capability for one scan disclosure write.
///
/// The installation/session owner selects the permitted durable storage
/// contour and issues this binding already bound to installation,
/// principal/session, host generation, discovery lease, privacy boundary and
/// `StateFence`/`AuthorityEpoch` (where available before `WorkScope`
/// creation), plus the operation/idempotency key, policy revision and
/// deadline. The capability carries no filesystem path: a caller cannot
/// choose a directory, UNC target or reparse destination because the API has
/// no path input at all. The durable owner admits the contour and performs
/// the write; the scanner only constructs and validates the receipt
/// candidate.
///
/// [`BootstrapScanner::scan`] admits the binding before any lease charge, so
/// a rejected binding fails closed without consuming the discovery lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanDisclosureOwnerBinding {
    pub installation_id: String,
    pub principal_ref: String,
    pub session_ref: String,
    pub host_generation_ref: String,
    pub lease_ref: String,
    pub candidate_root_ref: String,
    pub privacy_boundary_ref: String,
    pub state_fence_ref: Option<String>,
    pub authority_epoch_ref: Option<String>,
    pub operation_id: String,
    pub idempotency_key: String,
    /// Discovery lease consumption units already consumed when the owner
    /// issued this binding. [`BootstrapScanner::scan`] charges the lease
    /// before the write and refuses a binding that claims more consumption
    /// than the lease shows, so the write identity always names the lease
    /// operation window it rode on.
    pub lease_consumed: u64,
    pub policy_revision: u64,
    pub deadline: u64,
}

impl ScanDisclosureOwnerBinding {
    /// Admits an owner-issued binding without performing any durable work.
    ///
    /// # Errors
    ///
    /// Returns an error when any required identity reference is blank or
    /// carries control characters, an optional fence/epoch reference is
    /// present but blank, or the policy revision or deadline is zero.
    pub fn admit(&self) -> Result<(), WorkScopeError> {
        text(&self.installation_id, "scan_binding.installation_id")?;
        text(&self.principal_ref, "scan_binding.principal_ref")?;
        text(&self.session_ref, "scan_binding.session_ref")?;
        text(
            &self.host_generation_ref,
            "scan_binding.host_generation_ref",
        )?;
        text(&self.lease_ref, "scan_binding.lease_ref")?;
        text(&self.candidate_root_ref, "scan_binding.candidate_root_ref")?;
        text(
            &self.privacy_boundary_ref,
            "scan_binding.privacy_boundary_ref",
        )?;
        if let Some(fence) = &self.state_fence_ref {
            text(fence, "scan_binding.state_fence_ref")?;
        }
        if let Some(epoch) = &self.authority_epoch_ref {
            text(epoch, "scan_binding.authority_epoch_ref")?;
        }
        text(&self.operation_id, "scan_binding.operation_id")?;
        text(&self.idempotency_key, "scan_binding.idempotency_key")?;
        counter(self.policy_revision, "scan_binding.policy_revision")?;
        counter(self.deadline, "scan_binding.deadline")?;
        Ok(())
    }
    ///
    /// Derived from the installation identity alone: the durable owner, not
    /// the caller, owns the storage contour behind it.
    /// Owner/store identity this binding authorizes writes against.
    ///
    /// Derived from the installation identity alone: the durable owner, not
    /// the caller, owns the storage contour behind it.
    #[must_use]
    pub fn owner_ref(&self) -> String {
        format!("installation:{}:scan-disclosure", self.installation_id)
    }

    /// Immutable operation key for one write identity (I5.27 operation id).
    #[must_use]
    pub fn operation_key(&self) -> String {
        format!(
            "scan-disclosure:{}:{}",
            self.installation_id, self.operation_id
        )
    }

    /// Canonical request hash binding the exact receipt bytes to this write
    /// identity (I5.27 canonical request hash).
    ///
    /// The encoding is deterministic and versioned: domain separator,
    /// installation, idempotency namespace, encoding version, receipt digest,
    /// principal/scope binding, lease identity and consumed operation,
    /// operation identity and retention window all feed the hash, so reusing
    /// an idempotency key with different content conflicts instead of
    /// overwriting.
    #[must_use]
    pub fn request_hash(&self, receipt_digest: &str, schema_version: u32) -> String {
        sha256_hex(
            format!(
                "{domain}\n{idempotency_namespace}\n{encoding_version}\n{installation}\n{receipt_digest}\n{principal}:{session}:{host}:{lease}:{lease_consumed}:{root}:{boundary}\n{fence}:{epoch}\n{operation}:{idempotency}\n{policy}:{deadline}\n{schema_version}",
                domain = SCAN_DISCLOSURE_OPERATION_DOMAIN,
                idempotency_namespace = self.operation_key(),
                encoding_version = SCAN_DISCLOSURE_SCHEMA_VERSION,
                installation = self.installation_id,
                principal = self.principal_ref,
                session = self.session_ref,
                host = self.host_generation_ref,
                lease = self.lease_ref,
                lease_consumed = self.lease_consumed,
                root = self.candidate_root_ref,
                boundary = self.privacy_boundary_ref,
                fence = self.state_fence_ref.as_deref().unwrap_or("-"),
                epoch = self.authority_epoch_ref.as_deref().unwrap_or("-"),
                operation = self.operation_id,
                idempotency = self.idempotency_key,
                policy = self.policy_revision,
                deadline = self.deadline,
            )
            .as_bytes(),
        )
    }

    /// Immutable record commitment for one stored write: the operation key
    /// plus its canonical request hash.
    #[must_use]
    pub fn record_commitment(&self, receipt_digest: &str) -> String {
        format!(
            "{}:{}",
            self.operation_key(),
            self.request_hash(receipt_digest, SCAN_DISCLOSURE_SCHEMA_VERSION)
        )
    }
}

/// Retention/invalidation state of one durable scan receipt.
///
/// New scans never mutate prior evidence: a changed privacy boundary,
/// governing-source generation, root identity or scanner schema writes a new
/// record (optionally linked through `Superseded`), and retirement only marks
/// the record under an explicit policy revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanReceiptRetention {
    Active,
    Superseded { successor_ref: String },
    Retired { policy_revision: u64 },
}

impl ScanReceiptRetention {
    /// Validates the retention state without reading the store.
    ///
    /// # Errors
    ///
    /// Returns an error when a successor reference is blank or a retirement
    /// policy revision is zero.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        match self {
            Self::Active => Ok(()),
            Self::Superseded { successor_ref } => {
                text(successor_ref, "scan_retention.successor_ref")
            }
            Self::Retired { policy_revision } => {
                counter(*policy_revision, "scan_retention.policy_revision")
            }
        }
    }
}

/// Explicit bounded retention policy retiring scan receipts.
///
/// Retirement is always explicit: records are marked, never deleted, and stay
/// addressable as historical evidence under the policy revision that retired
/// them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanRetentionPolicy {
    pub policy_revision: u64,
    pub keep_generations: u64,
}

impl ScanRetentionPolicy {
    /// Validates the retention policy shape.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy revision or the retained generation
    /// bound is zero.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        counter(self.policy_revision, "scan_retention_policy.revision")?;
        counter(
            self.keep_generations,
            "scan_retention_policy.keep_generations",
        )
    }
}

/// Durable-write handle for one stored disclosure receipt.
///
/// `receipt_ref` names the scanned receipt (`ScanDisclosureReceipt::scan_ref`);
/// `store_ref` is the owner-qualified record key assigned by the durable
/// owner (opaque here). `owner_ref` carries the exact owner/store identity
/// the installation owner admitted, `record_commitment` the immutable
/// operation-key plus canonical-request-hash commitment,
/// `receipt_digest` the digest of the exact canonical receipt bytes,
/// `schema_version` the write-identity schema, `writer_receipt_ref` the
/// owner write receipt, and `retention` the retention/invalidation state.
/// The scanner verifies the full binding before reporting completion, and
/// the owner revalidates it on authenticated readback after restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanReceiptHandle {
    pub receipt_ref: String,
    pub store_ref: String,
    pub owner_ref: String,
    pub record_commitment: String,
    pub receipt_digest: String,
    pub schema_version: u32,
    pub writer_receipt_ref: String,
    pub retention: ScanReceiptRetention,
}

impl ScanReceiptHandle {
    /// Validates the handle shape without re-reading the store.
    ///
    /// # Errors
    ///
    /// Returns an error when any reference is blank or carries control
    /// characters, the receipt digest is not a digest, the retention state is
    /// malformed, or the schema version is stale for this binding.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.receipt_ref, "receipt_handle.receipt_ref")?;
        text(&self.store_ref, "receipt_handle.store_ref")?;
        text(&self.owner_ref, "receipt_handle.owner_ref")?;
        text(&self.record_commitment, "receipt_handle.record_commitment")?;
        digest(&self.receipt_digest, "receipt_handle.receipt_digest")?;
        if self.schema_version != SCAN_DISCLOSURE_SCHEMA_VERSION {
            return Err(WorkScopeError::ScanReceiptStale);
        }
        text(
            &self.writer_receipt_ref,
            "receipt_handle.writer_receipt_ref",
        )?;
        self.retention.validate()
    }
}

/// Bounded redacted diagnostic view of one stored receipt.
///
/// Carries opaque references and the immutable commitment only: no receipt
/// content, no allowed-class lists, no paths. Storage, backup/export and
/// diagnostics never let receipt references escape the admitted
/// privacy/storage boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanReceiptDiagnosticView {
    pub receipt_ref: String,
    pub owner_ref: String,
    pub record_commitment: String,
    pub schema_version: u32,
    pub retention: ScanReceiptRetention,
}

impl ScanReceiptDiagnosticView {
    /// Projects the bounded view from an admitted handle.
    ///
    /// # Errors
    ///
    /// Returns the handle validation error when the handle is malformed.
    pub fn project(handle: &ScanReceiptHandle) -> Result<Self, WorkScopeError> {
        handle.validate()?;
        Ok(Self {
            receipt_ref: handle.receipt_ref.clone(),
            owner_ref: handle.owner_ref.clone(),
            record_commitment: handle.record_commitment.clone(),
            schema_version: handle.schema_version,
            retention: handle.retention.clone(),
        })
    }
}

/// Quarantine proof for one loose `scan-disclosure-*.json` capture.
///
/// Files produced by the retired caller-chosen directory implementation
/// carry no owner provenance: a matching filename alone never adopts a file
/// as a receipt. Quarantine records the decision and leaves the bytes
/// untouched for the migration owner; it never returns a readable receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LooseScanQuarantine {
    pub file_name: String,
    pub reason: String,
    pub quarantined_as: String,
}

impl LooseScanQuarantine {
    /// Validates the quarantine proof shape.
    ///
    /// # Errors
    ///
    /// Returns an error when any proof reference is blank.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.file_name, "loose_scan_quarantine.file_name")?;
        text(&self.reason, "loose_scan_quarantine.reason")?;
        text(&self.quarantined_as, "loose_scan_quarantine.quarantined_as")
    }
}

/// Classifies one suspected loose scan disclosure capture.
///
/// A filename with the retired loose-capture shape is always quarantined and
/// never adopted: filename shape is not owner provenance. Any other blank
/// name fails closed.
///
/// # Errors
///
/// Returns an error when the filename is blank or does not carry the retired
/// loose-capture shape.
pub fn quarantine_loose_scan_disclosure(
    file_name: &str,
) -> Result<LooseScanQuarantine, WorkScopeError> {
    text(file_name, "loose_scan_file")?;
    if !file_name.starts_with(LOOSE_SCAN_DISCLOSURE_PREFIX)
        || !file_name.ends_with(LOOSE_SCAN_DISCLOSURE_SUFFIX)
    {
        return Err(WorkScopeError::InvalidText {
            field: "loose_scan_file",
        });
    }
    // The digest segment stays opaque: quarantine never parses a filename
    // into a receipt identity.
    let quarantine = LooseScanQuarantine {
        file_name: file_name.to_owned(),
        reason: "matching filename alone is not owner provenance; pre-created loose captures are never adopted as scan receipts"
            .to_owned(),
        quarantined_as: format!("quarantined:{file_name}"),
    };
    quarantine.validate()?;
    Ok(quarantine)
}

/// Durable-write port for scan disclosure receipts.
///
/// The governor owns scan semantics but never owns store mechanics: the
/// installation/session owner selects the permitted durable storage contour
/// and issues the [`ScanDisclosureOwnerBinding`], the canonical Store/ORS
/// owner writes, replays, reads and retires the record behind this port, and
/// the cold-start/attach owner consumes only the retained owner receipt.
/// [`BootstrapScanner::scan`] reports `Completed` only after the write
/// succeeds and the returned handle binds the receipt and the binding. A
/// scan whose receipt cannot be durably written is an error, never a
/// completion without proof.
///
/// Implementations must publish atomically: a partial or crashed write stays
/// `Prepared`/`Unknown` and reconciles the original operation through
/// [`ScanDisclosureStore::reconcile`]; it never permanently occupies the
/// final content address. Exact replay returns the same stored receipt;
/// reusing an operation identity with changed bytes or bindings conflicts.
pub trait ScanDisclosureStore {
    /// Durably writes one disclosure receipt under the owner binding and
    /// returns its owner receipt handle.
    ///
    /// # Errors
    ///
    /// Returns an error when the binding or receipt is malformed, the contour
    /// is not admitted, the identity conflicts with retained state, or the
    /// write cannot be durably published; the scan then fails instead of
    /// completing without a persisted receipt.
    fn store_receipt(
        &mut self,
        binding: &ScanDisclosureOwnerBinding,
        receipt: &ScanDisclosureReceipt,
    ) -> Result<ScanReceiptHandle, WorkScopeError>;

    /// Reads back and authenticates one stored receipt after restart:
    /// recomputes the canonical bytes/digest and validates the request
    /// binding. Never treats missing, inaccessible, corrupt, replaced,
    /// stale, invalidated or unknown-commit records as completed receipts.
    ///
    /// # Errors
    ///
    /// Returns the typed record cause instead of a completed receipt.
    fn readback(
        &self,
        handle: &ScanReceiptHandle,
        binding: &ScanDisclosureOwnerBinding,
    ) -> Result<ScanDisclosureReceipt, WorkScopeError>;

    /// Reconciles a lost write response against the original operation: a
    /// retained `Prepared` record commits, an exact `Committed` record
    /// replays, and anything else reports its typed cause. Reconciliation
    /// never blindly creates another record.
    ///
    /// # Errors
    ///
    /// Returns [`WorkScopeError::ScanReceiptUnknownCommit`] when no retained
    /// operation exists for the binding, or the conflicting cause.
    fn reconcile(
        &mut self,
        binding: &ScanDisclosureOwnerBinding,
    ) -> Result<ScanReceiptHandle, WorkScopeError>;

    /// Retires one stored receipt under an explicit retention policy. The
    /// record is marked, never deleted, and stays addressable as historical
    /// evidence; new scans write new records and never mutate prior ones.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy, handle or binding is malformed, or
    /// the retained record disagrees with the handle commitment.
    fn retire(
        &mut self,
        handle: &ScanReceiptHandle,
        binding: &ScanDisclosureOwnerBinding,
        policy: &ScanRetentionPolicy,
    ) -> Result<ScanReceiptHandle, WorkScopeError>;
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
/// scope authority. Bounded governing-source candidates travel into the
/// request on `governing_source_refs` as opaque references; their content is
/// never admitted here.
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
    /// candidate set plus the bounded governing-source references, and
    /// nothing else.
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
            governing_source_refs: self.governing_source_refs.clone(),
            supporting_evidence: Vec::new(),
        })
    }
}

/// What one deterministic bootstrap scan produced.
///
/// `Completed` carries the profile, the disclosure receipt, the durable-write
/// handle binding that receipt, and the bounded resolver inputs.
/// `PrivacyBoundaryRequired` carries the agent-facing code and a non-persisted
/// discriminative question; nothing is persisted on that path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "disposition", content = "detail")]
pub enum BootstrapScanOutcome {
    Completed {
        profile: Box<ProvisionalScopeProfile>,
        receipt: Box<ScanDisclosureReceipt>,
        persisted: Box<ScanReceiptHandle>,
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
    /// Runs one privacy-bounded scan against the lease key, lease, owner
    /// binding, boundary, and store.
    ///
    /// The owner binding is admitted before any lease charge: a binding the
    /// installation owner did not issue fails closed without consuming the
    /// discovery lease. The lease must have been issued for `key`: the scanner
    /// re-derives the
    /// lease reference through [`DiscoveryReadLease::key_matches`] before any
    /// other use, and a key mismatch fails closed without consumption. The
    /// forbidden-operation guard ([`deny_forbidden_operations`]) runs before
    /// charging, so every charged read passed an explicit denial of the
    /// forbidden operations. The caller's attested read classes must equal
    /// the populated evidence classes exactly; the lease must authorize every
    /// collected allowed class, and one consumption unit is charged per
    /// collected class. The privacy boundary must admit `candidate_privacy`;
    /// otherwise the outcome is `PrivacyBoundaryRequired` with only a
    /// non-persisted discriminative question. The disclosure receipt is
    /// durably written through `store` before completion is reported, and the
    /// returned handle must bind the receipt. Verifier candidates come from
    /// the caller (the owner's registered verifier references), never from
    /// synthesis: an empty list is recorded as a capability gap instead of a
    /// silent empty profile field.
    ///
    /// # Errors
    ///
    /// Returns [`WorkScopeError`] when the lease key, lease shape, evidence,
    /// attestation, verifier candidates, or scan references are malformed,
    /// when the key binding, forbidden-operation guard, attestation, receipt
    /// write, or handle binding fails, and when the lease is expired,
    /// exhausted, or does not admit a collected class.
    #[allow(
        clippy::too_many_arguments,
        reason = "scan joins key, lease, owner binding, store, boundary, evidence, and profile inputs in one deterministic constructor"
    )]
    pub fn scan(
        scan_ref: impl Into<String>,
        lease: &mut DiscoveryReadLease,
        key: &DiscoveryLeaseKey,
        store: &mut impl ScanDisclosureStore,
        binding: &ScanDisclosureOwnerBinding,
        candidate_privacy: PrivacyClass,
        privacy_boundary: Option<&PrivacyBoundary>,
        evidence: &BootstrapScanEvidence,
        proposed_kind: ScopeKind,
        identity_fingerprint: impl Into<String>,
        verifier_candidates: &[String],
        governing_source_refs: Vec<String>,
        now: u64,
    ) -> Result<BootstrapScanOutcome, WorkScopeError> {
        let scan_ref = scan_ref.into();
        let identity_fingerprint = identity_fingerprint.into();
        text(&scan_ref, "scan_ref")?;
        text(&identity_fingerprint, "identity_fingerprint")?;
        key.validate()?;
        binding.admit()?;
        lease
            .validate()
            .map_err(|_| WorkScopeError::InvalidCounter { field: "lease" })?;
        if !lease.key_matches(
            &key.proposer_ref,
            &key.session_ref,
            &key.host_ref,
            &key.root_filesystem_identity_ref,
        ) {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        evidence.validate()?;
        check_verifier_candidates(verifier_candidates)?;
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
        deny_forbidden_operations()?;
        let collected = collected_classes(evidence);
        check_attested_reads(&collected, &evidence.attested_reads)?;
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
        if binding.lease_consumed > u64::from(lease.consumed) {
            return Err(WorkScopeError::ScanContourNotAdmitted);
        }
        let bytes =
            canonical_json_bytes(&receipt).map_err(|_| WorkScopeError::ScanReceiptInaccessible)?;
        let receipt_digest = sha256_hex(&bytes);
        let persisted = store.store_receipt(binding, &receipt)?;
        persisted.validate()?;
        if persisted.receipt_ref != receipt.scan_ref
            || persisted.owner_ref != binding.owner_ref()
            || persisted.receipt_digest != receipt_digest
            || persisted.record_commitment != binding.record_commitment(&receipt_digest)
        {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        let profile = Self::profile_for(
            &scan_ref,
            proposed_kind,
            identity_fingerprint,
            evidence,
            &collected,
            verifier_candidates,
        )?;
        Ok(BootstrapScanOutcome::Completed {
            profile: Box::new(profile),
            receipt: Box::new(receipt),
            persisted: Box::new(persisted),
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
        verifier_candidates: &[String],
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
        if verifier_candidates.is_empty() {
            capability_gaps.push("verifiers".to_owned());
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
            verifier_candidates: verifier_candidates.to_vec(),
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

/// Production inputs for one bootstrap discovery run.
///
/// `observed` carries the live resources the host layer actually read (VCS,
/// filesystem, and process observations); `policy` carries what the owner
/// asserts, including the registered verifier references that become the
/// profile's verifier candidates; `evidence` carries the host layer's
/// per-class metadata for the candidate root. The runner binds all three
/// together before any scan runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapDiscoveryInputs {
    pub scan_ref: String,
    pub candidate_privacy: PrivacyClass,
    pub privacy_boundary: Option<PrivacyBoundary>,
    pub observed: ObservedScopeResources,
    pub policy: DescriptorPolicy,
    pub evidence: BootstrapScanEvidence,
    pub proposed_kind: ScopeKind,
    pub identity_fingerprint: String,
    pub governing_source_refs: Vec<String>,
    pub now: u64,
}

/// Runs the production bootstrap discovery flow: keyed lease, owner-bound
/// store, guarded scan, durable receipt write.
///
/// This is the non-test caller that wires the seams together. It validates
/// the live observations and owner policy, binds the scan evidence to what
/// was actually observed (the candidate root must be an observed root, the
/// filesystem identity must be an observed instance identity, and carried
/// VCS references must equal the observed generation exactly — arbitrary
/// caller strings that name nothing observed fail closed), checks the owner
/// binding against the lease and the privacy boundary, takes the
/// verifier candidates from the owner's registered verifier references, and
/// runs [`BootstrapScanner::scan`], which verifies the lease key, runs the
/// forbidden-operation guard, charges the lease, and durably writes the
/// receipt through the installation-bound `store` before reporting
/// completion. The caller never chooses storage: `store` is the injected
/// owner port already bound to the installation contour.
///
/// Exclusion holds by construction: the intake types have no fields for
/// command lines, recent output, neighboring roots, or raw secret literals,
/// and redaction identities must already be non-reversible digests.
///
/// # Errors
///
/// Returns an error when the owner binding disagrees with the lease or the
/// privacy boundary, when observations, policy, evidence, or references are
/// malformed, when evidence names nothing observed, or when the scan itself
/// fails (see [`BootstrapScanner::scan`]).
pub fn run_bootstrap_discovery(
    store: &mut impl ScanDisclosureStore,
    binding: &ScanDisclosureOwnerBinding,
    lease: &mut DiscoveryReadLease,
    key: &DiscoveryLeaseKey,
    discovery: &BootstrapDiscoveryInputs,
) -> Result<BootstrapScanOutcome, WorkScopeError> {
    text(&discovery.scan_ref, "discovery.scan_ref")?;
    text(
        &discovery.identity_fingerprint,
        "discovery.identity_fingerprint",
    )?;
    binding.admit()?;
    if binding.lease_ref != lease.lease_ref
        || binding.candidate_root_ref != lease.candidate_root_ref
    {
        return Err(WorkScopeError::ScanContourNotAdmitted);
    }
    if discovery
        .privacy_boundary
        .as_ref()
        .is_some_and(|boundary| binding.privacy_boundary_ref != boundary.boundary_ref)
    {
        return Err(WorkScopeError::ScanContourNotAdmitted);
    }
    discovery.observed.validate()?;
    discovery.policy.validate()?;
    discovery.evidence.validate()?;
    if !discovery
        .observed
        .root_identities
        .contains(&lease.candidate_root_ref)
    {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    if discovery.evidence.canonical_root_ref != lease.candidate_root_ref {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    if !discovery
        .observed
        .instances
        .iter()
        .any(|instance| instance.root_identity == discovery.evidence.filesystem_identity_ref)
    {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    let generation = &discovery.observed.generation;
    if discovery.evidence.vcs_branch_ref != generation.branch_ref
        || discovery.evidence.vcs_commit_ref != generation.commit_ref
        || discovery.evidence.vcs_dirty_summary_ref != generation.dirty_summary_ref
    {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    BootstrapScanner::scan(
        discovery.scan_ref.clone(),
        lease,
        key,
        store,
        binding,
        discovery.candidate_privacy,
        discovery.privacy_boundary.as_ref(),
        &discovery.evidence,
        discovery.proposed_kind,
        discovery.identity_fingerprint.clone(),
        &discovery.policy.verifier_refs,
        discovery.governing_source_refs.clone(),
        discovery.now,
    )
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

/// Requires the caller's attested read classes to equal the populated
/// evidence classes exactly.
///
/// Unattested populated classes mean the caller collected without admitting
/// the read; attested-but-empty classes mean the caller charges consumption
/// for nothing collected. Both fail closed before any charge.
///
/// # Errors
///
/// Returns [`WorkScopeError::BindingReceiptMismatch`] when the attested set
/// differs from the collected set in either direction.
fn check_attested_reads(
    collected: &[DiscoveryRead],
    attested: &[DiscoveryRead],
) -> Result<(), WorkScopeError> {
    if collected.len() != attested.len() || collected.iter().any(|class| !attested.contains(class))
    {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    Ok(())
}

/// Validates caller-supplied verifier candidates without interpreting them.
///
/// # Errors
///
/// Returns an error when a candidate is blank or duplicated, or more than 32
/// candidates are carried.
fn check_verifier_candidates(candidates: &[String]) -> Result<(), WorkScopeError> {
    if candidates.len() > 32 {
        return Err(WorkScopeError::EmptyCollection {
            field: "verifier_candidates",
        });
    }
    for candidate in candidates {
        text(candidate, "verifier_candidates")?;
    }
    unique(candidates.iter(), "verifier_candidates")
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
