//! Rebuildable change observations and deterministic historical-anchor
//! resolution.
//!
//! `ChangeMonitor` is an observation/projection component.  It does not watch a
//! filesystem, open Git, execute tools, persist canonical history, or infer
//! causal authority.  Adapters submit bounded observations; this crate
//! validates, deduplicates, projects, and resolves them against explicit
//! candidates.  Canonical semantic transitions remain owned by Governor.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_contracts::{AnchorReference, AnchorResolution, AnchorResolutionStatus};
use eliot_contracts::{
    ContractError, ContractIdentity, ContractVersion, StateFence, canonical_json_bytes,
    contract_identity as foundation_contract_identity, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this Governor projection contract.
pub const CONTRACT_NAME: &str = "eliot.governor.change-monitor";
/// Current wire revision of this contract.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 1, 0);

/// Typed failures for observation admission and anchor resolution.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChangeMonitorError {
    /// A shared foundation contract rejected an identity or fence.
    #[error("foundation contract: {0}")]
    Foundation(ContractError),
    /// An existing observation identity was reused for different content.
    #[error("observation identity conflict")]
    IdentityConflict,
    /// A required field is blank or malformed.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },
    /// A required collection was empty.
    #[error("empty field {field}")]
    Empty {
        /// Stable field path.
        field: &'static str,
    },
    /// A collection contained duplicate identities.
    #[error("duplicate values in {field}")]
    Duplicate {
        /// Stable field path.
        field: &'static str,
    },
    /// A before/after pair did not describe a real change.
    #[error("change observation has no changed resource")]
    NoChangedResource,
    /// An observation marked unknown origin while carrying a false exact link.
    #[error("unknown-origin observation cannot claim exact attribution")]
    UnknownOriginAttribution,
    /// A reconciliation did not identify admitted observations that prove the same change.
    #[error("unknown-change reconciliation evidence is invalid")]
    InvalidReconciliation,
    /// A host/filesystem hint is malformed or uses a producer-only origin.
    #[error("change hint is invalid")]
    InvalidHint,
    /// A hint verification lacks matching content, Git, or re-read evidence.
    #[error("change hint verification is invalid")]
    InvalidHintVerification,
    /// A governed tool mutation lacks exact attempt, operation, diff, revision,
    /// or State Fence invalidation evidence.
    #[error("governed tool mutation receipt is incomplete or inconsistent")]
    InvalidGovernedMutationReceipt,
    /// Material evidence reached the generic observation ingress instead of
    /// an owner-specific admission path.
    #[error("material change requires a trusted owner admission path")]
    UntrustedMaterialIngress,
    /// A resolver candidate did not carry a valid public anchor.
    #[error("invalid anchor candidate")]
    InvalidAnchor,
}

impl From<ContractError> for ChangeMonitorError {
    fn from(error: ContractError) -> Self {
        Self::Foundation(error)
    }
}

impl From<eliot_agent_contracts::ContractError> for ChangeMonitorError {
    fn from(_error: eliot_agent_contracts::ContractError) -> Self {
        // Agent contract errors intentionally remain distinct at their own
        // surface; this projection exposes only a stable invalid-anchor class.
        Self::InvalidAnchor
    }
}

fn text(value: &str, field: &'static str) -> Result<(), ChangeMonitorError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ChangeMonitorError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_relative_path(value: &str, field: &'static str) -> Result<(), ChangeMonitorError> {
    text(value, field)?;
    if value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains(':')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ChangeMonitorError::InvalidField {
            field,
            reason: "must be a normalized repository-relative path",
        });
    }
    Ok(())
}

fn unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), ChangeMonitorError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(ChangeMonitorError::Duplicate { field });
    }
    Ok(())
}

fn is_material_mutation(kind: ChangeKind) -> bool {
    matches!(
        kind,
        ChangeKind::Created | ChangeKind::Modified | ChangeKind::Deleted | ChangeKind::Renamed
    )
}

fn validate_governed_tool_mutation(
    observation: &ChangeObservation,
) -> Result<(), ChangeMonitorError> {
    observation.validate()?;
    let Some(attempt_receipt_ref) = observation.origin_ref.as_deref() else {
        return Err(ChangeMonitorError::InvalidGovernedMutationReceipt);
    };
    let Some(operation_ref) = observation.operation_ref.as_deref() else {
        return Err(ChangeMonitorError::InvalidGovernedMutationReceipt);
    };
    let Some(diff_ref) = observation.diff_or_artifact_ref.as_deref() else {
        return Err(ChangeMonitorError::InvalidGovernedMutationReceipt);
    };
    text(attempt_receipt_ref, "governed_mutation.attempt_receipt")?;
    text(operation_ref, "governed_mutation.operation_ref")?;
    text(diff_ref, "governed_mutation.diff_ref")?;

    if observation.origin != ChangeOrigin::ProcessToolReceipt
        || !is_material_mutation(observation.kind)
        || observation.unknown_origin
        || !matches!(
            observation.attribution,
            Attribution::Exact | Attribution::ReceiptLinked
        )
    {
        return Err(ChangeMonitorError::InvalidGovernedMutationReceipt);
    }

    let (resource, expected_kind) = match (&observation.before, &observation.after) {
        (None, Some(after)) => (after, ChangeKind::Created),
        (Some(before), None) => (before, ChangeKind::Deleted),
        (Some(before), Some(after)) if before.resource_ref == after.resource_ref => {
            if before.revision == after.revision {
                return Err(ChangeMonitorError::InvalidGovernedMutationReceipt);
            }
            let kind = if before.path == after.path {
                ChangeKind::Modified
            } else {
                ChangeKind::Renamed
            };
            (after, kind)
        }
        _ => return Err(ChangeMonitorError::InvalidGovernedMutationReceipt),
    };
    for snapshot in [&observation.before, &observation.after]
        .into_iter()
        .flatten()
    {
        if snapshot
            .content_digest
            .as_deref()
            .is_none_or(|digest| !is_sha256_hex(digest))
        {
            return Err(ChangeMonitorError::InvalidGovernedMutationReceipt);
        }
    }
    if observation.kind != expected_kind
        || !observation.invalidations.iter().any(|invalidation| {
            invalidation.dependency == format!("resource:{}", resource.resource_ref)
                && invalidation.state_fence == observation.state_fence
                && invalidation.reason_ref == attempt_receipt_ref
        })
    {
        return Err(ChangeMonitorError::InvalidGovernedMutationReceipt);
    }
    Ok(())
}

fn hint_observation_id(
    role: &str,
    hint: &ChangeHint,
    verification: &ChangeHintVerification,
) -> Result<String, ChangeMonitorError> {
    let bytes = canonical_json_bytes(&(role, hint, verification)).map_err(|_| {
        ChangeMonitorError::InvalidField {
            field: "hint_verification",
            reason: "cannot serialize verification identity",
        }
    })?;
    Ok(format!("change-hint:{role}:{}", sha256_hex(&bytes)))
}

/// Origin route for one host/tool observation.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOrigin {
    HostEvent,
    FilesystemNotification,
    GitReconciliation,
    ProcessToolReceipt,
    ArtifactScan,
    HumanObservation,
    Unknown,
}

/// Confidence of attribution, deliberately separate from epistemic truth.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    Exact,
    ReceiptLinked,
    Correlated,
    Ambiguous,
    Unknown,
}

/// Kind of observed resource mutation.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Created,
    Modified,
    Deleted,
    Renamed,
    ArtifactProduced,
    ProcessObserved,
    ToolObserved,
}

/// Bounded identity and content snapshot for a resource before or after an
/// observation.  Payload bytes remain in Blob/Artifact stores and are never
/// embedded here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSnapshot {
    /// Stable resource identity.
    pub resource_ref: String,
    /// Revision observed for this resource.
    pub revision: String,
    /// Optional normalized path.
    pub path: Option<String>,
    /// Optional source symbol/AST identity.
    pub symbol: Option<String>,
    /// Optional content digest.
    pub content_digest: Option<String>,
    /// Optional structural-neighborhood digest.
    pub structural_digest: Option<String>,
}

impl ResourceSnapshot {
    /// Validates identity metadata without interpreting source content.
    pub fn validate(&self) -> Result<(), ChangeMonitorError> {
        text(&self.resource_ref, "resource_ref")?;
        text(&self.revision, "resource_revision")?;
        if let Some(path) = &self.path {
            text(path, "resource_path")?;
        }
        if let Some(symbol) = &self.symbol {
            text(symbol, "resource_symbol")?;
        }
        if let Some(digest) = &self.content_digest {
            text(digest, "content_digest")?;
        }
        if let Some(digest) = &self.structural_digest {
            text(digest, "structural_digest")?;
        }
        Ok(())
    }
}

/// Explicit State Fence dependency invalidated by an observed change.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceInvalidation {
    /// Dependency key whose previous decision may no longer apply.
    pub dependency: String,
    /// Fence at which the dependency was observed invalidated.
    pub state_fence: StateFence,
    /// Public reason/observation handle.
    pub reason_ref: String,
}

impl FenceInvalidation {
    /// Validates the invalidation without deciding downstream authority.
    pub fn validate(&self) -> Result<(), ChangeMonitorError> {
        text(&self.dependency, "invalidation.dependency")?;
        self.state_fence.validate()?;
        text(&self.reason_ref, "invalidation.reason_ref")
    }
}

/// One immutable host/filesystem/Git/tool/artifact observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeObservation {
    /// Idempotent observation identity.
    pub change_id: String,
    /// State Fence captured by the producer.
    pub state_fence: StateFence,
    /// Mutation kind.
    pub kind: ChangeKind,
    /// Resource state before the observation, when available.
    pub before: Option<ResourceSnapshot>,
    /// Resource state after the observation, when available.
    pub after: Option<ResourceSnapshot>,
    /// Capture route.
    pub origin: ChangeOrigin,
    /// Attribution confidence.
    pub attribution: Attribution,
    /// Exact source/receipt/tool reference when one exists.
    pub origin_ref: Option<String>,
    /// Session associated with the observation, if known.
    pub session_ref: Option<String>,
    /// Action lease associated with the observation, if known.
    pub action_lease_ref: Option<String>,
    /// Tool operation or attempt identity, if known.
    pub operation_ref: Option<String>,
    /// Exact diff/artifact handle, if known.
    pub diff_or_artifact_ref: Option<String>,
    /// Explicit unknown-origin marker for reconciliation gates.
    pub unknown_origin: bool,
    /// Fences invalidated by this observation.
    #[serde(default)]
    pub invalidations: Vec<FenceInvalidation>,
}

impl ChangeObservation {
    /// Validates a complete bounded observation.
    pub fn validate(&self) -> Result<(), ChangeMonitorError> {
        text(&self.change_id, "change_id")?;
        self.state_fence.validate()?;
        let Some(changed) = self.before.as_ref().or(self.after.as_ref()) else {
            return Err(ChangeMonitorError::NoChangedResource);
        };
        changed.validate()?;
        if let Some(before) = &self.before {
            before.validate()?;
        }
        if let Some(after) = &self.after {
            after.validate()?;
        }
        if let (Some(before), Some(after)) = (&self.before, &self.after)
            && before == after
        {
            return Err(ChangeMonitorError::NoChangedResource);
        }
        if self.unknown_origin
            && matches!(
                self.attribution,
                Attribution::Exact | Attribution::ReceiptLinked
            )
        {
            return Err(ChangeMonitorError::UnknownOriginAttribution);
        }
        if self.origin == ChangeOrigin::Unknown && !self.unknown_origin {
            return Err(ChangeMonitorError::UnknownOriginAttribution);
        }
        for reference in [
            self.origin_ref.as_ref(),
            self.session_ref.as_ref(),
            self.action_lease_ref.as_ref(),
            self.operation_ref.as_ref(),
            self.diff_or_artifact_ref.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            text(reference, "change_reference")?;
        }
        unique(
            self.invalidations
                .iter()
                .map(|item| item.dependency.clone()),
            "invalidations",
        )?;
        for invalidation in &self.invalidations {
            invalidation.validate()?;
        }
        Ok(())
    }

    /// Computes the stable digest used for idempotent replay detection.
    pub fn digest(&self) -> Result<String, ChangeMonitorError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|_| ChangeMonitorError::InvalidField {
            field: "change_observation",
            reason: "cannot serialize observation",
        })?;
        Ok(sha256_hex(&bytes))
    }

    fn resource_ref(&self) -> &str {
        self.after
            .as_ref()
            .or(self.before.as_ref())
            .map_or("", |resource| resource.resource_ref.as_str())
    }
}

/// Result of ingesting one observation into the rebuildable projection.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestDisposition {
    Accepted,
    Replayed,
}

/// Non-authoritative acknowledgement returned by the local projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationAdmission {
    /// Observation identity.
    pub change_id: String,
    /// Content digest used for replay identity.
    pub observation_digest: String,
    /// Local projection disposition.
    pub disposition: IngestDisposition,
    /// Whether downstream acceptance must pause for reconciliation.
    pub acceptance_blocked: bool,
    /// Exact invalidation dependencies exposed to consumers.
    pub invalidation_dependencies: Vec<String>,
}

/// Immutable record held by the rebuildable `ChangeMonitor` projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedChangeRecord {
    /// Original observation.
    pub observation: ChangeObservation,
    /// Content digest for deterministic replay.
    pub observation_digest: String,
}

/// Rebuildable `ChangeMonitor` view.  It can be reconstructed from observation
/// records and does not supersede canonical source history.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeMonitorSnapshot {
    /// Immutable observations in accepted insertion order. This sequence is
    /// required to rebuild the current-resource projection after repeated
    /// mutations to the same resource.
    pub observations: Vec<ObservedChangeRecord>,
    /// Explicit links from unknown-origin material changes to admitted evidence.
    #[serde(default)]
    pub reconciliations: Vec<UnknownChangeReconciliation>,
    /// Host/filesystem hints and their verified content/Git readbacks.
    ///
    /// A pending hint is not itself a material observation, but it blocks
    /// governed acceptance until verified. A verified material result adds an
    /// unknown-origin observation and a separate Git evidence observation;
    /// the latter does not reconcile the former automatically.
    #[serde(default)]
    pub hints: Vec<ChangeHintRecord>,
    /// Current resource projection by stable resource identity.
    pub current_resources: Vec<ResourceSnapshot>,
    /// Dependencies observed invalidated by any included change.
    pub invalidated_dependencies: Vec<String>,
}

/// A rebuildable projection link from one immutable unknown-origin change to
/// a separate admitted observation that proves the same resource transition.
/// This link is not a canonical observation or an authority decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownChangeReconciliation {
    /// Immutable unknown-origin material observation being reconciled.
    pub unknown_change_id: String,
    /// Separate immutable evidence observation for the exact same transition.
    pub evidence_change_id: String,
}

/// Untrusted host/filesystem event supplied to the monitor as a re-check hint.
///
/// Hints do not assert that a material change occurred. The adapter must read
/// the resource, collect Git evidence, and re-read its content before the
/// monitor emits a material observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeHint {
    /// Idempotent host-event identity.
    pub hint_id: String,
    /// State Fence at which the adapter received the event.
    pub state_fence: StateFence,
    /// Stable identity of the hinted resource.
    pub resource_ref: String,
    /// Canonical repository-relative path supplied by the adapter.
    pub path: String,
    /// Host event or filesystem notification route.
    pub origin: ChangeOrigin,
    /// Exact host event/notification receipt, when available.
    pub origin_ref: Option<String>,
}

impl ChangeHint {
    /// Validates the untrusted event identity and its narrow source route.
    pub fn validate(&self) -> Result<(), ChangeMonitorError> {
        text(&self.hint_id, "hint_id")?;
        self.state_fence.validate()?;
        text(&self.resource_ref, "hint.resource_ref")?;
        validate_relative_path(&self.path, "hint.path")?;
        if !matches!(
            self.origin,
            ChangeOrigin::HostEvent | ChangeOrigin::FilesystemNotification
        ) {
            return Err(ChangeMonitorError::InvalidHint);
        }
        if let Some(origin_ref) = &self.origin_ref {
            text(origin_ref, "hint.origin_ref")?;
        }
        Ok(())
    }
}

/// Presence/digest result from one direct content read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContentReadState {
    /// The path existed and the exact bytes hashed to this SHA-256 digest.
    Present { sha256: String },
    /// The path was absent when read (used for a confirmed deletion).
    Absent,
}

impl ContentReadState {
    fn validate(&self) -> Result<(), ChangeMonitorError> {
        if let Self::Present { sha256 } = self
            && !is_sha256_hex(sha256)
        {
            return Err(ChangeMonitorError::InvalidHintVerification);
        }
        Ok(())
    }
}

/// Bounded Git status/diff evidence from the trusted Kernel readback adapter.
///
/// Host request payloads must never deserialize into this value. The adapter
/// constructs it only from successful read-only Git invocations and binds its
/// changed-path list to the same direct content reads as the verification.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitChangeEvidence {
    /// Stable repository identity/root handle.
    pub repository_ref: String,
    /// Repository HEAD observed before the first direct content read.
    pub head_before: String,
    /// Repository HEAD observed after the independent content re-read.
    pub head_after: String,
    /// Exact read-only Git status receipt captured before the first read.
    pub status_before_ref: String,
    /// SHA-256 of the exact status bytes captured before the first read.
    pub status_before_sha256: String,
    /// Exact read-only Git status receipt captured after the re-read.
    pub status_ref: String,
    /// SHA-256 of the exact status bytes captured after the re-read.
    pub status_sha256: String,
    /// Previously admitted resource revision bound to the first status read.
    pub before_resource_revision: Option<String>,
    /// Re-read resource revision bound to the second status read.
    pub after_resource_revision: Option<String>,
    /// Exact material diff/artifact handle, when Git reports a change.
    pub diff_ref: Option<String>,
    /// Canonical repository-relative paths reported by Git as changed.
    pub changed_paths: Vec<String>,
    /// Exact Git rename pairs reported by the same status/diff readback.
    pub renames: Vec<GitPathRename>,
}

impl GitChangeEvidence {
    fn validate(&self) -> Result<(), ChangeMonitorError> {
        for (value, field) in [
            (&self.repository_ref, "git.repository_ref"),
            (&self.head_before, "git.head_before"),
            (&self.head_after, "git.head_after"),
            (&self.status_before_ref, "git.status_before_ref"),
            (&self.status_ref, "git.status_ref"),
        ] {
            text(value, field)?;
        }
        if self.status_before_ref == self.status_ref
            || !is_sha256_hex(&self.status_before_sha256)
            || !is_sha256_hex(&self.status_sha256)
        {
            return Err(ChangeMonitorError::InvalidHintVerification);
        }
        for revision in [
            &self.before_resource_revision,
            &self.after_resource_revision,
        ]
        .into_iter()
        .flatten()
        {
            text(revision, "git.resource_revision")?;
        }
        if let Some(diff_ref) = &self.diff_ref {
            text(diff_ref, "git.diff_ref")?;
        }
        unique(self.changed_paths.iter().cloned(), "git.changed_paths")?;
        for path in &self.changed_paths {
            validate_relative_path(path, "git.changed_path")?;
        }
        unique(
            self.renames.iter().map(|rename| rename.old_path.clone()),
            "git.renames.old_path",
        )?;
        unique(
            self.renames.iter().map(|rename| rename.new_path.clone()),
            "git.renames.new_path",
        )?;
        for rename in &self.renames {
            rename.validate()?;
            if !self.changed_paths.contains(&rename.old_path)
                || !self.changed_paths.contains(&rename.new_path)
            {
                return Err(ChangeMonitorError::InvalidHintVerification);
            }
        }
        Ok(())
    }
}

/// One exact old/new path pair reported by Git rename detection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitPathRename {
    /// Former repository-relative path.
    pub old_path: String,
    /// New repository-relative path.
    pub new_path: String,
}

impl GitPathRename {
    fn validate(&self) -> Result<(), ChangeMonitorError> {
        validate_relative_path(&self.old_path, "git.rename.old_path")?;
        validate_relative_path(&self.new_path, "git.rename.new_path")?;
        if self.old_path == self.new_path {
            return Err(ChangeMonitorError::InvalidHintVerification);
        }
        Ok(())
    }
}

/// Exact content and Git readbacks used to promote one hint into observations.
///
/// This is an internal adapter result, not a caller-supplied event payload.
/// A trusted owner-side adapter must construct it from actual file reads and
/// read-only Git receipts. Host transport routes must accept only
/// [`ChangeHint`] and must not deserialize user payloads into this type.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeHintVerification {
    /// Previously admitted state, when the producer has one.
    pub before: Option<ResourceSnapshot>,
    /// State observed by the first post-hint content read.
    pub after: Option<ResourceSnapshot>,
    /// Repository-relative path read by the first direct content read.
    pub first_read_path: String,
    /// First read result at `first_read_path`.
    pub first_read: ContentReadState,
    /// Receipt for the first direct file read.
    pub first_read_ref: String,
    /// Repository-relative path read by the independent content re-read.
    pub reread_path: String,
    /// Independent re-read result; must equal `first_read` and `after`.
    pub reread: ContentReadState,
    /// Receipt for the independent direct file re-read.
    pub reread_ref: String,
    /// Git read-only status/diff evidence over the same hinted path.
    pub git: GitChangeEvidence,
}

impl ChangeHintVerification {
    #[allow(
        clippy::too_many_lines,
        reason = "one readback must validate its complete bound evidence before classification"
    )]
    fn kind_for(&self, hint: &ChangeHint) -> Result<Option<ChangeKind>, ChangeMonitorError> {
        self.first_read.validate()?;
        self.reread.validate()?;
        self.git.validate()?;
        validate_relative_path(&self.first_read_path, "hint.first_read_path")?;
        validate_relative_path(&self.reread_path, "hint.reread_path")?;
        text(&self.first_read_ref, "hint.first_read_ref")?;
        text(&self.reread_ref, "hint.reread_ref")?;
        if self.first_read_ref == self.reread_ref
            || self.first_read_path != self.reread_path
            || self.first_read != self.reread
            || self.git.head_before != self.git.head_after
        {
            return Err(ChangeMonitorError::InvalidHintVerification);
        }
        if let Some(before) = &self.before {
            before.validate()?;
            let Some(path) = before.path.as_deref() else {
                return Err(ChangeMonitorError::InvalidHintVerification);
            };
            validate_relative_path(path, "before.path")?;
            if before.resource_ref != hint.resource_ref
                || before
                    .content_digest
                    .as_deref()
                    .is_none_or(|digest| !is_sha256_hex(digest))
                || self.git.before_resource_revision.as_deref() != Some(before.revision.as_str())
            {
                return Err(ChangeMonitorError::InvalidHintVerification);
            }
        } else if self.git.before_resource_revision.is_some() {
            return Err(ChangeMonitorError::InvalidHintVerification);
        }
        if let Some(after) = &self.after {
            after.validate()?;
            let Some(path) = after.path.as_deref() else {
                return Err(ChangeMonitorError::InvalidHintVerification);
            };
            validate_relative_path(path, "after.path")?;
            if after.resource_ref != hint.resource_ref
                || after
                    .content_digest
                    .as_deref()
                    .is_none_or(|digest| !is_sha256_hex(digest))
                || self.first_read
                    != (ContentReadState::Present {
                        sha256: after.content_digest.clone().unwrap_or_default(),
                    })
                || self.git.after_resource_revision.as_deref() != Some(after.revision.as_str())
                || self.first_read_path != path
            {
                return Err(ChangeMonitorError::InvalidHintVerification);
            }
        } else if self.first_read != ContentReadState::Absent
            || self.git.after_resource_revision.is_some()
            || self.first_read_path
                != self
                    .before
                    .as_ref()
                    .and_then(|resource| resource.path.as_deref())
                    .unwrap_or_default()
        {
            return Err(ChangeMonitorError::InvalidHintVerification);
        }

        let kind = match (&self.before, &self.after) {
            (None, None) => None,
            (None, Some(_)) => Some(ChangeKind::Created),
            (Some(_), None) => Some(ChangeKind::Deleted),
            (Some(before), Some(after)) if before == after => None,
            (Some(before), Some(after)) if before.path != after.path => Some(ChangeKind::Renamed),
            (Some(_), Some(_)) => Some(ChangeKind::Modified),
        };
        let before_path = self
            .before
            .as_ref()
            .and_then(|resource| resource.path.as_ref());
        let after_path = self
            .after
            .as_ref()
            .and_then(|resource| resource.path.as_ref());
        if before_path.is_none_or(|path| path != &hint.path)
            && after_path.is_none_or(|path| path != &hint.path)
        {
            return Err(ChangeMonitorError::InvalidHintVerification);
        }
        if kind.is_none() && self.before.is_none() && self.after.is_none() {
            return Err(ChangeMonitorError::InvalidHintVerification);
        }
        let mut affected_paths = BTreeSet::new();
        if let Some(path) = before_path {
            validate_relative_path(path, "before.path")?;
            affected_paths.insert(path.as_str());
        }
        if let Some(path) = after_path {
            validate_relative_path(path, "after.path")?;
            affected_paths.insert(path.as_str());
        }
        let reported_paths: BTreeSet<&str> =
            self.git.changed_paths.iter().map(String::as_str).collect();
        let git_reports_change = affected_paths
            .iter()
            .any(|path| reported_paths.contains(*path));
        if (kind.is_some()
            && (affected_paths
                .iter()
                .any(|path| !reported_paths.contains(*path))
                || !git_reports_change
                || self.git.diff_ref.is_none()))
            || (kind.is_none() && git_reports_change)
        {
            return Err(ChangeMonitorError::InvalidHintVerification);
        }
        if kind == Some(ChangeKind::Renamed) {
            let before_path = before_path.ok_or(ChangeMonitorError::InvalidHintVerification)?;
            let after_path = after_path.ok_or(ChangeMonitorError::InvalidHintVerification)?;
            if !self
                .git
                .renames
                .iter()
                .any(|rename| rename.old_path == *before_path && rename.new_path == *after_path)
            {
                return Err(ChangeMonitorError::InvalidHintVerification);
            }
        }
        Ok(kind)
    }
}

/// Persisted hint and, once present, the evidence that resolved it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeHintRecord {
    /// Original host/filesystem hint.
    pub hint: ChangeHint,
    /// Missing while the adapter has not completed its content/Git readback.
    pub verification: Option<ChangeHintVerification>,
}

/// Result of admitting a host/filesystem hint.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeHintAdmission {
    /// Hint identity.
    pub hint_id: String,
    /// Whether this is the first admission or an identical replay.
    pub disposition: IngestDisposition,
    /// Whether any pending hint or unknown material change still blocks
    /// governed acceptance.
    pub acceptance_blocked: bool,
}

/// Result of verifying one admitted hint.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeHintConfirmation {
    /// Hint identity.
    pub hint_id: String,
    /// `true` when the verified resource state is unchanged.
    pub unchanged: bool,
    /// Unknown-origin material observation, present only for a changed file.
    pub unknown_change_id: Option<String>,
    /// Separate Git-only state evidence; it cannot attribute the change or
    /// clear the unknown-origin blocker by itself.
    pub evidence_change_id: Option<String>,
    /// Whether the acceptance gate remains closed after this operation.
    pub acceptance_blocked: bool,
}

/// In-memory rebuildable projection over immutable observations.
#[derive(Clone, Debug, Default)]
pub struct ChangeMonitor {
    observations: BTreeMap<String, ObservedChangeRecord>,
    observation_order: Vec<String>,
    reconciliations: BTreeMap<String, UnknownChangeReconciliation>,
    hints: BTreeMap<String, ChangeHintRecord>,
    hint_order: Vec<String>,
    current_resources: BTreeMap<String, ResourceSnapshot>,
    invalidated_dependencies: BTreeSet<String>,
}

impl ChangeMonitor {
    /// Rebuilds the monitor from canonical immutable observations.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "preserve the published owned snapshot rebuild API"
    )]
    pub fn from_snapshot(snapshot: ChangeMonitorSnapshot) -> Result<Self, ChangeMonitorError> {
        let mut monitor = Self::default();
        for record in &snapshot.hints {
            monitor.ingest_hint(record.hint.clone())?;
        }
        let mut hint_material_ids = BTreeMap::new();
        for record in &snapshot.hints {
            if let Some(verification) = &record.verification
                && verification.kind_for(&record.hint)?.is_some()
            {
                for role in ["unknown", "git"] {
                    let change_id = hint_observation_id(role, &record.hint, verification)?;
                    if hint_material_ids
                        .insert(change_id, record.hint.hint_id.clone())
                        .is_some()
                    {
                        return Err(ChangeMonitorError::IdentityConflict);
                    }
                }
            }
        }
        let mut replayed_hint_confirmations = BTreeSet::new();
        for record in &snapshot.observations {
            let observed = record.observation.clone();
            if observed.digest()? != record.observation_digest {
                return Err(ChangeMonitorError::IdentityConflict);
            }
            if is_material_mutation(observed.kind)
                && matches!(
                    observed.origin,
                    ChangeOrigin::HostEvent
                        | ChangeOrigin::FilesystemNotification
                        | ChangeOrigin::GitReconciliation
                )
            {
                // Only material rows regenerated from a persisted verified
                // hint are accepted. Triggering regeneration at the first
                // matching row preserves the original cross-origin effect
                // order; raw host/Git rows cannot seed the projection.
                let hint_id = hint_material_ids
                    .get(&observed.change_id)
                    .ok_or(ChangeMonitorError::InvalidHintVerification)?
                    .clone();
                if replayed_hint_confirmations.insert(hint_id.clone()) {
                    let verification = snapshot
                        .hints
                        .iter()
                        .find(|record| record.hint.hint_id == hint_id)
                        .and_then(|record| record.verification.clone())
                        .ok_or(ChangeMonitorError::InvalidHintVerification)?;
                    monitor.confirm_hint_inner(&hint_id, &verification, true)?;
                }
                let regenerated = monitor
                    .observations
                    .get(&observed.change_id)
                    .ok_or(ChangeMonitorError::InvalidHintVerification)?;
                if regenerated.observation != observed
                    || regenerated.observation_digest != record.observation_digest
                {
                    return Err(ChangeMonitorError::IdentityConflict);
                }
                continue;
            }
            if is_material_mutation(observed.kind)
                && observed.origin == ChangeOrigin::ProcessToolReceipt
            {
                // Retained rows cross the same narrow evidence-shape boundary
                // as live governed mutations, including the projected
                // preimage at their retained insertion position.
                validate_governed_tool_mutation(&observed)?;
            } else if is_material_mutation(observed.kind) {
                // Material rows enter through a verified host hint or the
                // narrow governed-tool owner path. Do not let persisted
                // ArtifactScan/Git/other rows self-assert admission or clear
                // an unknown-origin blocker during rebuild.
                return Err(ChangeMonitorError::UntrustedMaterialIngress);
            }
            monitor.ingest_observation(observed, true, true, true)?;
        }
        for record in &snapshot.hints {
            if let Some(verification) = &record.verification
                && !replayed_hint_confirmations.contains(&record.hint.hint_id)
            {
                // No-change confirmations do not alter the resource
                // projection and have no place in observation order. Their
                // readback remains retained; changed confirmations must have
                // appeared at their ordered material rows above.
                if verification.kind_for(&record.hint)?.is_some() {
                    return Err(ChangeMonitorError::InvalidHintVerification);
                }
                monitor.confirm_hint_inner(&record.hint.hint_id, verification, false)?;
            }
        }
        for reconciliation in &snapshot.reconciliations {
            monitor.reconcile_unknown_change(
                &reconciliation.unknown_change_id,
                &reconciliation.evidence_change_id,
            )?;
        }
        let rebuilt = monitor.snapshot();
        if rebuilt.observations != snapshot.observations
            || rebuilt.current_resources != snapshot.current_resources
            || monitor.snapshot().invalidated_dependencies != snapshot.invalidated_dependencies
            || monitor.snapshot().reconciliations != snapshot.reconciliations
            || rebuilt.hints != snapshot.hints
        {
            return Err(ChangeMonitorError::IdentityConflict);
        }
        Ok(monitor)
    }

    /// Ingests one non-material observation, treating an identical replay as
    /// idempotent. Material changes require their origin-specific owner path;
    /// a well-formed reference string is not readback or attribution proof.
    pub fn ingest(
        &mut self,
        observation: ChangeObservation,
    ) -> Result<ObservationAdmission, ChangeMonitorError> {
        if is_material_mutation(observation.kind) {
            return Err(ChangeMonitorError::UntrustedMaterialIngress);
        }
        self.ingest_observation(observation, false, false, true)
    }

    fn ingest_observation(
        &mut self,
        observation: ChangeObservation,
        from_verified_hint: bool,
        from_governed_mutation: bool,
        require_projected_preimage: bool,
    ) -> Result<ObservationAdmission, ChangeMonitorError> {
        if is_material_mutation(observation.kind)
            && matches!(
                observation.origin,
                ChangeOrigin::HostEvent | ChangeOrigin::FilesystemNotification
            )
            && !from_verified_hint
        {
            return Err(ChangeMonitorError::InvalidHintVerification);
        }
        if is_material_mutation(observation.kind)
            && observation.origin == ChangeOrigin::ProcessToolReceipt
            && !from_governed_mutation
        {
            return Err(ChangeMonitorError::InvalidGovernedMutationReceipt);
        }
        if require_projected_preimage
            && is_material_mutation(observation.kind)
            && observation.origin == ChangeOrigin::ProcessToolReceipt
            && observation.before.as_ref() != self.current_resources.get(observation.resource_ref())
        {
            return Err(ChangeMonitorError::InvalidGovernedMutationReceipt);
        }
        let digest = observation.digest()?;
        let change_id = observation.change_id.clone();
        if let Some(existing) = self.observations.get(&change_id) {
            if existing.observation_digest != digest {
                return Err(ChangeMonitorError::IdentityConflict);
            }
            return Ok(ObservationAdmission {
                change_id,
                observation_digest: digest,
                disposition: IngestDisposition::Replayed,
                acceptance_blocked: self.blocks_acceptance(),
                invalidation_dependencies: existing
                    .observation
                    .invalidations
                    .iter()
                    .map(|item| item.dependency.clone())
                    .collect(),
            });
        }
        if let Some(after) = &observation.after {
            self.current_resources
                .insert(after.resource_ref.clone(), after.clone());
        } else if let Some(before) = &observation.before {
            self.current_resources.remove(&before.resource_ref);
        }
        for invalidation in &observation.invalidations {
            self.invalidated_dependencies
                .insert(invalidation.dependency.clone());
        }
        let invalidation_dependencies = observation
            .invalidations
            .iter()
            .map(|item| item.dependency.clone())
            .collect();
        self.observations.insert(
            change_id.clone(),
            ObservedChangeRecord {
                observation,
                observation_digest: digest.clone(),
            },
        );
        self.observation_order.push(change_id.clone());
        let acceptance_blocked = self.blocks_acceptance();
        Ok(ObservationAdmission {
            change_id,
            observation_digest: digest,
            disposition: IngestDisposition::Accepted,
            acceptance_blocked,
            invalidation_dependencies,
        })
    }

    /// Admits a material change proven by one exact governed tool attempt.
    ///
    /// The receipt handle identifies the attempt; `operation_ref` identifies
    /// the exact tool operation and `diff_or_artifact_ref` binds its output.
    /// Before/after resource revisions remain on the observation, while the
    /// invalidation must bind this exact State Fence and attempt receipt. This
    /// narrow path is for a Governor owner after independent content/Git
    /// readback; host payloads never call it. The first mutation of a resource
    /// cannot pass until that owner has admitted a verified baseline.
    pub fn ingest_governed_tool_mutation(
        &mut self,
        observation: ChangeObservation,
    ) -> Result<ObservationAdmission, ChangeMonitorError> {
        validate_governed_tool_mutation(&observation)?;
        if observation.before.as_ref() != self.current_resources.get(observation.resource_ref()) {
            return Err(ChangeMonitorError::InvalidGovernedMutationReceipt);
        }
        self.ingest_observation(observation, false, true, true)
    }

    /// Admits an untrusted host/filesystem event as a pending re-check hint.
    ///
    /// Pending hints block governed acceptance until a verified no-change
    /// readback or a material transition is reconciled explicitly.
    pub fn ingest_hint(
        &mut self,
        hint: ChangeHint,
    ) -> Result<ChangeHintAdmission, ChangeMonitorError> {
        hint.validate()?;
        let hint_id = hint.hint_id.clone();
        if let Some(existing) = self.hints.get(&hint_id) {
            if existing.hint != hint {
                return Err(ChangeMonitorError::IdentityConflict);
            }
            return Ok(ChangeHintAdmission {
                hint_id,
                disposition: IngestDisposition::Replayed,
                acceptance_blocked: self.blocks_acceptance(),
            });
        }
        self.hints.insert(
            hint_id.clone(),
            ChangeHintRecord {
                hint,
                verification: None,
            },
        );
        self.hint_order.push(hint_id.clone());
        Ok(ChangeHintAdmission {
            hint_id,
            disposition: IngestDisposition::Accepted,
            acceptance_blocked: self.blocks_acceptance(),
        })
    }

    fn confirm_hint_inner(
        &mut self,
        hint_id: &str,
        verification: &ChangeHintVerification,
        require_projected_before: bool,
    ) -> Result<ChangeHintConfirmation, ChangeMonitorError> {
        text(hint_id, "hint_id")?;
        let record = self
            .hints
            .get(hint_id)
            .ok_or(ChangeMonitorError::InvalidHint)?;
        let hint = record.hint.clone();
        let kind = verification.kind_for(&hint)?;
        if let Some(existing) = &record.verification {
            if existing != verification {
                return Err(ChangeMonitorError::IdentityConflict);
            }
            return self.hint_confirmation(&hint, verification, kind);
        }
        // A missing projection is not evidence that the path was absent. The
        // trusted producer must first admit an owner-verified baseline for an
        // existing file before a first external mutation can be classified.
        if require_projected_before
            && verification.before.as_ref() != self.current_resources.get(&hint.resource_ref)
        {
            return Err(ChangeMonitorError::InvalidHintVerification);
        }

        if let Some(kind) = kind {
            let unknown_change_id = hint_observation_id("unknown", &hint, verification)?;
            let evidence_change_id = hint_observation_id("git", &hint, verification)?;
            let reason_ref = format!("change-hint:{}", hint.hint_id);
            let unknown_observation = ChangeObservation {
                change_id: unknown_change_id.clone(),
                state_fence: hint.state_fence.clone(),
                kind,
                before: verification.before.clone(),
                after: verification.after.clone(),
                origin: hint.origin,
                attribution: Attribution::Unknown,
                origin_ref: Some(
                    hint.origin_ref
                        .clone()
                        .unwrap_or_else(|| format!("host-hint:{}", hint.hint_id)),
                ),
                session_ref: None,
                action_lease_ref: None,
                operation_ref: None,
                diff_or_artifact_ref: None,
                unknown_origin: true,
                invalidations: vec![FenceInvalidation {
                    dependency: format!("resource:{}", hint.resource_ref),
                    state_fence: hint.state_fence.clone(),
                    reason_ref,
                }],
            };
            let evidence_observation = ChangeObservation {
                change_id: evidence_change_id.clone(),
                state_fence: hint.state_fence.clone(),
                kind,
                before: verification.before.clone(),
                after: verification.after.clone(),
                origin: ChangeOrigin::GitReconciliation,
                // This row records observed bytes and Git state only; it says
                // nothing about which actor caused the transition.
                attribution: Attribution::Unknown,
                origin_ref: Some(verification.git.status_ref.clone()),
                session_ref: None,
                action_lease_ref: None,
                operation_ref: None,
                diff_or_artifact_ref: verification.git.diff_ref.clone(),
                unknown_origin: false,
                invalidations: Vec::new(),
            };
            let unknown_digest = unknown_observation.digest()?;
            let evidence_digest = evidence_observation.digest()?;
            let pair_already_admitted = match (
                self.observations.get(&unknown_change_id),
                self.observations.get(&evidence_change_id),
            ) {
                (None, None) => false,
                (Some(unknown), Some(evidence))
                    if unknown.observation_digest == unknown_digest
                        && evidence.observation_digest == evidence_digest =>
                {
                    true
                }
                _ => return Err(ChangeMonitorError::IdentityConflict),
            };
            if !pair_already_admitted {
                // Both rows and identities have been validated before either
                // can mutate the projection, preventing a half-admitted pair
                // if the second ID is already occupied or malformed.
                self.ingest_observation(unknown_observation, true, false, false)?;
                self.ingest_observation(evidence_observation, false, false, false)?;
            }
        }
        self.hints
            .get_mut(hint_id)
            .ok_or(ChangeMonitorError::InvalidHint)?
            .verification = Some(verification.clone());
        self.hint_confirmation(&hint, verification, kind)
    }

    fn hint_confirmation(
        &self,
        hint: &ChangeHint,
        verification: &ChangeHintVerification,
        kind: Option<ChangeKind>,
    ) -> Result<ChangeHintConfirmation, ChangeMonitorError> {
        let (unknown_change_id, evidence_change_id) = if kind.is_some() {
            (
                Some(hint_observation_id("unknown", hint, verification)?),
                Some(hint_observation_id("git", hint, verification)?),
            )
        } else {
            (None, None)
        };
        Ok(ChangeHintConfirmation {
            hint_id: hint.hint_id.clone(),
            unchanged: kind.is_none(),
            unknown_change_id,
            evidence_change_id,
            acceptance_blocked: self.blocks_acceptance(),
        })
    }

    /// Returns a deterministic snapshot suitable for rebuilding consumers.
    pub fn snapshot(&self) -> ChangeMonitorSnapshot {
        ChangeMonitorSnapshot {
            observations: self
                .observation_order
                .iter()
                .filter_map(|change_id| self.observations.get(change_id).cloned())
                .collect(),
            reconciliations: self.reconciliations.values().cloned().collect(),
            hints: self
                .hint_order
                .iter()
                .filter_map(|hint_id| self.hints.get(hint_id).cloned())
                .collect(),
            current_resources: self.current_resources.values().cloned().collect(),
            invalidated_dependencies: self.invalidated_dependencies.iter().cloned().collect(),
        }
    }

    /// Reconciles an unknown-origin material change against a separate
    /// admitted observation only when both prove the exact same before/after
    /// resource snapshots under the same State Fence. Git status/diff evidence
    /// confirms content state but cannot establish who caused the mutation;
    /// the clearing evidence must be an attributable process/tool receipt or
    /// artifact scan carrying an operation or diff/artifact handle. This
    /// conservative projection does not treat a host event, human observation,
    /// or filesystem notification alone as confirmation.
    /// Repeated exact links are idempotent; a conflicting link is rejected.
    /// This projection creates no canonical history or acceptance authority;
    /// callers must supply admitted canonical observations.
    pub fn reconcile_unknown_change(
        &mut self,
        unknown_change_id: &str,
        evidence_change_id: &str,
    ) -> Result<(), ChangeMonitorError> {
        text(unknown_change_id, "reconciliation.unknown_change_id")?;
        text(evidence_change_id, "reconciliation.evidence_change_id")?;
        let unknown = self
            .observations
            .get(unknown_change_id)
            .ok_or(ChangeMonitorError::InvalidReconciliation)?;
        let evidence = self
            .observations
            .get(evidence_change_id)
            .ok_or(ChangeMonitorError::InvalidReconciliation)?;
        if !unknown.observation.unknown_origin
            || !is_material_mutation(unknown.observation.kind)
            || !is_material_mutation(evidence.observation.kind)
            || evidence.observation.unknown_origin
            || !matches!(
                evidence.observation.origin,
                ChangeOrigin::ProcessToolReceipt | ChangeOrigin::ArtifactScan
            )
            || !matches!(
                evidence.observation.attribution,
                Attribution::Exact | Attribution::ReceiptLinked
            )
            || evidence.observation.origin_ref.is_none()
            || (evidence.observation.operation_ref.is_none()
                && evidence.observation.diff_or_artifact_ref.is_none())
            || evidence.observation.kind != unknown.observation.kind
            || evidence.observation.state_fence != unknown.observation.state_fence
            || evidence.observation.before != unknown.observation.before
            || evidence.observation.after != unknown.observation.after
            || (evidence.observation.origin == ChangeOrigin::ProcessToolReceipt
                && validate_governed_tool_mutation(&evidence.observation).is_err())
        {
            return Err(ChangeMonitorError::InvalidReconciliation);
        }

        let link = UnknownChangeReconciliation {
            unknown_change_id: unknown_change_id.to_owned(),
            evidence_change_id: evidence_change_id.to_owned(),
        };
        if let Some(existing) = self.reconciliations.get(unknown_change_id) {
            if existing == &link {
                return Ok(());
            }
            return Err(ChangeMonitorError::IdentityConflict);
        }
        self.reconciliations
            .insert(unknown_change_id.to_owned(), link);
        Ok(())
    }

    fn has_unresolved_unknown_change(&self, change_id: &str) -> bool {
        self.observations.get(change_id).is_some_and(|record| {
            record.observation.unknown_origin
                && is_material_mutation(record.observation.kind)
                && !self.reconciliations.contains_key(change_id)
        })
    }

    /// Returns whether any unknown-origin material mutation blocks acceptance.
    pub fn has_unknown_material_change(&self) -> bool {
        self.observations
            .keys()
            .any(|change_id| self.has_unresolved_unknown_change(change_id))
    }

    /// Returns whether unverified hints or unreconciled material changes
    /// currently block governed acceptance.
    pub fn blocks_acceptance(&self) -> bool {
        self.has_pending_hints() || self.has_unknown_material_change()
    }

    /// Returns whether a host/filesystem hint still needs a verified
    /// content/Git readback.
    pub fn has_pending_hints(&self) -> bool {
        self.hints
            .values()
            .any(|record| record.verification.is_none())
    }
}

/// Candidate current location supplied by VCS/content/code-intelligence
/// adapters.  The adapters own discovery; the resolver owns only comparison.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorCandidate {
    /// Current public anchor reference.
    pub reference: AnchorReference,
    /// Optional content fingerprint.
    pub content_digest: Option<String>,
    /// Optional structural-neighborhood fingerprint.
    pub structural_digest: Option<String>,
    /// Whether VCS/history matched the original range.
    pub historical_range_match: bool,
}

impl AnchorCandidate {
    /// Validates the public reference and candidate fingerprints.
    pub fn validate(&self) -> Result<(), ChangeMonitorError> {
        self.reference
            .validate()
            .map_err(ChangeMonitorError::from)?;
        for digest in [&self.content_digest, &self.structural_digest]
            .into_iter()
            .flatten()
        {
            text(digest, "anchor_candidate.digest")?;
        }
        Ok(())
    }
}

/// Version of the deterministic evolving-anchor resolution order.
pub const EVOLVING_ANCHOR_RESOLVER_ALGORITHM_VERSION: &str = "evolving-anchor-resolver/v2";

/// Evidence tier that produced a resolver observation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorResolutionBasis {
    /// The complete immutable anchor reference matched exactly.
    ExactAnchorReference,
    /// Exact provenance or an operation/diff observation linked both revisions.
    ProvenanceIdentity,
    /// The exact immutable target artifact and revision matched.
    TargetRevision,
    /// Both the exact file path and symbol identity matched.
    ExactFileAndSymbol,
    /// The original content digest and structural-neighborhood digest matched.
    ContentAndStructuralFingerprint,
    /// A VCS/history adapter matched the original historical range.
    HistoricalRange,
    /// A matching immutable deletion observation was present.
    DeletionObservation,
    /// No current candidate was available.
    NoCandidates,
    /// Candidates existed but no identity evidence matched.
    NoMatch,
}

/// Evidence strength for a resolver observation, not a probability estimate.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorResolutionConfidence {
    /// A complete anchor, provenance, artifact, file/symbol, or deletion identity matched.
    ExactIdentity,
    /// Both independent content and structural-neighborhood digests matched.
    Corroborated,
    /// Only an explicit historical-range match was available.
    HistoricalOnly,
    /// No matching evidence supported a current target.
    Unresolved,
}

/// Immutable identity and digest for one `ChangeMonitor` input observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorResolverObservationReference {
    /// Idempotent `ChangeMonitor` observation identity.
    pub change_id: String,
    /// Digest of the complete immutable observation.
    pub observation_digest: String,
}

/// Evidence selected by one resolution pass.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorResolutionEvidence {
    /// First matching tier in the resolver's precedence order.
    pub basis: AnchorResolutionBasis,
    /// Indices into `AnchorResolutionObservation::candidate_inputs` that matched.
    pub candidate_indices: Vec<u32>,
    /// Indices into `AnchorResolutionObservation::monitor_observation_inputs` used as evidence.
    pub monitor_observation_indices: Vec<u32>,
}

/// Rebuildable, evidence-bearing result over an immutable original anchor.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorResolutionObservation {
    /// Algorithm version used for this result.
    pub algorithm_version: String,
    /// Immutable original anchor supplied to the resolver.
    pub original_anchor: AnchorReference,
    /// Complete candidate inputs supplied to the resolver.
    pub candidate_inputs: Vec<AnchorCandidate>,
    /// Complete observation identities examined for deletion evidence.
    pub monitor_observation_inputs: Vec<AnchorResolverObservationReference>,
    /// Evidence tier and exact inputs that matched it.
    pub evidence: AnchorResolutionEvidence,
    /// Evidence strength for the selected tier, independent of target uniqueness.
    pub confidence: AnchorResolutionConfidence,
    /// Existing wire-compatible resolution projection.
    pub resolution: AnchorResolution,
}

fn candidate_location_status(
    original: &AnchorReference,
    candidate: &AnchorReference,
) -> AnchorResolutionStatus {
    let same_location = candidate.path == original.path
        && candidate.symbol == original.symbol
        && candidate.line_start == original.line_start
        && candidate.line_end == original.line_end;
    if same_location {
        AnchorResolutionStatus::Modified
    } else {
        AnchorResolutionStatus::Moved
    }
}

fn snapshot_matches_target(
    snapshot: &ResourceSnapshot,
    target: &eliot_agent_contracts::PublicReference,
) -> bool {
    snapshot.resource_ref == target.id.as_str()
        && snapshot.revision == target.revision.as_str()
        && target
            .digest
            .as_ref()
            .is_none_or(|digest| snapshot.content_digest.as_ref() == Some(digest))
}

fn observation_links_provenance(
    observation: &ChangeObservation,
    original: &AnchorReference,
    candidate: &AnchorCandidate,
) -> bool {
    let Some(provenance) = original.provenance.as_ref() else {
        return false;
    };
    let exact_provenance = candidate.reference.provenance.as_ref() == Some(provenance);
    let exact_symbol = original
        .symbol
        .as_ref()
        .is_some_and(|symbol| candidate.reference.symbol.as_ref() == Some(symbol));
    let source_id = provenance.source_id.as_str();
    let exact_operation_or_diff = observation.operation_ref.as_deref() == Some(source_id)
        || observation.diff_or_artifact_ref.as_deref() == Some(source_id);
    exact_provenance
        && exact_symbol
        && candidate.reference.target.kind == original.target.kind
        && exact_operation_or_diff
        && observation
            .before
            .as_ref()
            .is_some_and(|before| snapshot_matches_target(before, &original.target))
        && observation
            .after
            .as_ref()
            .is_some_and(|after| snapshot_matches_target(after, &candidate.reference.target))
}

/// Deterministic resolver over immutable original identity and explicit
/// current candidates.
#[derive(Clone, Copy, Debug, Default)]
pub struct EvolvingAnchorResolver;

impl EvolvingAnchorResolver {
    /// Resolves one historical anchor without nearest-neighbour attachment.
    #[allow(
        clippy::too_many_lines,
        reason = "resolution order is priority-sensitive and kept contiguous to preserve deterministic status precedence"
    )]
    pub fn resolve(
        &self,
        original: &AnchorReference,
        candidates: &[AnchorCandidate],
        monitor: &ChangeMonitorSnapshot,
    ) -> Result<AnchorResolution, ChangeMonitorError> {
        self.resolve_observed(original, candidates, monitor)
            .map(|observation| observation.resolution)
    }

    /// Resolves one historical anchor and records the exact inputs and evidence tier.
    #[allow(
        clippy::too_many_lines,
        reason = "resolution order is priority-sensitive and kept contiguous to preserve deterministic status precedence"
    )]
    pub fn resolve_observed(
        &self,
        original: &AnchorReference,
        candidates: &[AnchorCandidate],
        monitor: &ChangeMonitorSnapshot,
    ) -> Result<AnchorResolutionObservation, ChangeMonitorError> {
        original.validate().map_err(ChangeMonitorError::from)?;
        for candidate in candidates {
            candidate.validate()?;
        }
        let _validated_monitor = ChangeMonitor::from_snapshot(monitor.clone())?;
        let anchor_id = original.anchor_id.clone();
        let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
        let monitor_observation_inputs: Vec<AnchorResolverObservationReference> = monitor
            .observations
            .iter()
            .map(|record| AnchorResolverObservationReference {
                change_id: record.observation.change_id.clone(),
                observation_digest: record.observation_digest.clone(),
            })
            .collect();
        let observe = |status: AnchorResolutionStatus,
                       current_reference: Option<AnchorReference>,
                       basis: AnchorResolutionBasis,
                       candidate_indices: Vec<u32>,
                       monitor_observation_indices: Vec<u32>,
                       confidence: AnchorResolutionConfidence| {
            AnchorResolutionObservation {
                algorithm_version: EVOLVING_ANCHOR_RESOLVER_ALGORITHM_VERSION.to_owned(),
                original_anchor: original.clone(),
                candidate_inputs: candidates.to_vec(),
                monitor_observation_inputs: monitor_observation_inputs.clone(),
                evidence: AnchorResolutionEvidence {
                    basis,
                    candidate_indices,
                    monitor_observation_indices,
                },
                confidence,
                resolution: AnchorResolution {
                    anchor_id: anchor_id.clone(),
                    status,
                    current_reference,
                    candidate_count,
                },
            }
        };
        let candidate_indices = |predicate: &dyn Fn(&AnchorCandidate) -> bool| {
            candidates
                .iter()
                .enumerate()
                .filter(|(_, candidate)| predicate(candidate))
                .map(|(index, _)| u32::try_from(index).unwrap_or(u32::MAX))
                .collect::<Vec<_>>()
        };
        let resolution_for_matches =
            |indices: &[u32],
             basis: AnchorResolutionBasis,
             confidence: AnchorResolutionConfidence| {
                if indices.len() == 1 {
                    let candidate = &candidates[indices[0] as usize];
                    observe(
                        candidate_location_status(original, &candidate.reference),
                        Some(candidate.reference.clone()),
                        basis,
                        indices.to_vec(),
                        Vec::new(),
                        confidence,
                    )
                } else {
                    observe(
                        AnchorResolutionStatus::Ambiguous,
                        None,
                        basis,
                        indices.to_vec(),
                        Vec::new(),
                        confidence,
                    )
                }
            };

        let exact = candidate_indices(&|candidate| &candidate.reference == original);
        if !exact.is_empty() {
            if exact.len() == 1 {
                return Ok(observe(
                    AnchorResolutionStatus::Exact,
                    Some(candidates[exact[0] as usize].reference.clone()),
                    AnchorResolutionBasis::ExactAnchorReference,
                    exact,
                    Vec::new(),
                    AnchorResolutionConfidence::ExactIdentity,
                ));
            }
            return Ok(resolution_for_matches(
                &exact,
                AnchorResolutionBasis::ExactAnchorReference,
                AnchorResolutionConfidence::ExactIdentity,
            ));
        }

        let provenance_matches = candidate_indices(&|candidate| {
            monitor.observations.iter().any(|record| {
                observation_links_provenance(&record.observation, original, candidate)
            })
        });
        if !provenance_matches.is_empty() {
            let mut evidence_indices = BTreeSet::new();
            for candidate_index in &provenance_matches {
                let candidate = &candidates[*candidate_index as usize];
                for (observation_index, record) in monitor.observations.iter().enumerate() {
                    if observation_links_provenance(&record.observation, original, candidate) {
                        evidence_indices
                            .insert(u32::try_from(observation_index).unwrap_or(u32::MAX));
                    }
                }
            }
            if provenance_matches.len() == 1 {
                let candidate = &candidates[provenance_matches[0] as usize];
                return Ok(observe(
                    candidate_location_status(original, &candidate.reference),
                    Some(candidate.reference.clone()),
                    AnchorResolutionBasis::ProvenanceIdentity,
                    provenance_matches,
                    evidence_indices.into_iter().collect(),
                    AnchorResolutionConfidence::ExactIdentity,
                ));
            }
            return Ok(observe(
                AnchorResolutionStatus::Ambiguous,
                None,
                AnchorResolutionBasis::ProvenanceIdentity,
                provenance_matches,
                evidence_indices.into_iter().collect(),
                AnchorResolutionConfidence::ExactIdentity,
            ));
        }

        let same_target_revision = candidate_indices(&|candidate| {
            candidate.reference.target == original.target
                && candidate_location_status(original, &candidate.reference)
                    == AnchorResolutionStatus::Modified
        });
        if !same_target_revision.is_empty() {
            return Ok(resolution_for_matches(
                &same_target_revision,
                AnchorResolutionBasis::TargetRevision,
                AnchorResolutionConfidence::ExactIdentity,
            ));
        }

        let exact_file_and_symbol = candidate_indices(&|candidate| {
            candidate.reference.target == original.target
                && original
                    .path
                    .as_ref()
                    .is_some_and(|path| candidate.reference.path.as_ref() == Some(path))
                && original
                    .symbol
                    .as_ref()
                    .is_some_and(|symbol| candidate.reference.symbol.as_ref() == Some(symbol))
        });
        if !exact_file_and_symbol.is_empty() {
            return Ok(resolution_for_matches(
                &exact_file_and_symbol,
                AnchorResolutionBasis::ExactFileAndSymbol,
                AnchorResolutionConfidence::ExactIdentity,
            ));
        }

        let fingerprint_matches = candidate_indices(&|candidate| {
            original
                .target
                .digest
                .as_ref()
                .is_some_and(|content_digest| {
                    candidate.content_digest.as_ref() == Some(content_digest)
                })
                && candidate.structural_digest.as_deref() == Some(original.context_digest.as_str())
        });
        if !fingerprint_matches.is_empty() {
            return Ok(resolution_for_matches(
                &fingerprint_matches,
                AnchorResolutionBasis::ContentAndStructuralFingerprint,
                AnchorResolutionConfidence::Corroborated,
            ));
        }

        let historical_matches = candidate_indices(&|candidate| candidate.historical_range_match);
        if !historical_matches.is_empty() {
            return Ok(resolution_for_matches(
                &historical_matches,
                AnchorResolutionBasis::HistoricalRange,
                AnchorResolutionConfidence::HistoricalOnly,
            ));
        }

        let deletion_indices: Vec<u32> = monitor
            .observations
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                record.observation.kind == ChangeKind::Deleted
                    && record.observation.resource_ref() == original.target.id.as_str()
            })
            .map(|(index, _)| u32::try_from(index).unwrap_or(u32::MAX))
            .collect();
        if !deletion_indices.is_empty() {
            return Ok(observe(
                AnchorResolutionStatus::Deleted,
                None,
                AnchorResolutionBasis::DeletionObservation,
                Vec::new(),
                deletion_indices,
                AnchorResolutionConfidence::ExactIdentity,
            ));
        }

        if candidates.is_empty() {
            return Ok(observe(
                AnchorResolutionStatus::Unavailable,
                None,
                AnchorResolutionBasis::NoCandidates,
                Vec::new(),
                Vec::new(),
                AnchorResolutionConfidence::Unresolved,
            ));
        }

        Ok(observe(
            AnchorResolutionStatus::Stale,
            None,
            AnchorResolutionBasis::NoMatch,
            Vec::new(),
            Vec::new(),
            AnchorResolutionConfidence::Unresolved,
        ))
    }
}

/// Attribution class for a bidirectional provenance edge.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceAttribution {
    Exact,
    ReceiptLinked,
    Correlated,
    Ambiguous,
    Unknown,
}

/// One public edge in the rebuildable change-provenance view.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceEdge {
    /// Source public handle.
    pub from_ref: String,
    /// Target public handle.
    pub to_ref: String,
    /// Non-causal relation label.
    pub relation: String,
    /// Evidence-grounded attribution class.
    pub attribution: ProvenanceAttribution,
    /// Exact observations/receipts supporting the edge.
    pub evidence_refs: Vec<String>,
}

impl ProvenanceEdge {
    /// Validates an edge without promoting correlation to causality.
    pub fn validate(&self) -> Result<(), ChangeMonitorError> {
        text(&self.from_ref, "provenance.from_ref")?;
        text(&self.to_ref, "provenance.to_ref")?;
        text(&self.relation, "provenance.relation")?;
        unique(self.evidence_refs.iter(), "provenance.evidence_refs")?;
        for reference in &self.evidence_refs {
            text(reference, "provenance.evidence_ref")?;
        }
        Ok(())
    }
}

/// Rebuildable bidirectional view consumed by `CodeCortex` and review surfaces.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeProvenanceView {
    /// Fence under which links were composed.
    pub state_fence: StateFence,
    /// Public links in deterministic order.
    pub edges: Vec<ProvenanceEdge>,
    /// Links that could not be resolved without inventing continuity.
    pub unresolved_refs: Vec<String>,
}

impl ChangeProvenanceView {
    /// Builds a validated view from explicit edge candidates.
    pub fn new(
        state_fence: StateFence,
        mut edges: Vec<ProvenanceEdge>,
        mut unresolved_refs: Vec<String>,
    ) -> Result<Self, ChangeMonitorError> {
        state_fence.validate()?;
        for edge in &edges {
            edge.validate()?;
        }
        for reference in &unresolved_refs {
            text(reference, "provenance.unresolved_ref")?;
        }
        edges.sort_by(|left, right| {
            left.from_ref
                .cmp(&right.from_ref)
                .then(left.to_ref.cmp(&right.to_ref))
                .then(left.relation.cmp(&right.relation))
        });
        unresolved_refs.sort();
        unresolved_refs.dedup();
        Ok(Self {
            state_fence,
            edges,
            unresolved_refs,
        })
    }

    /// Returns the reverse-direction edges for a current target.
    pub fn inbound(&self, target: &str) -> Vec<&ProvenanceEdge> {
        self.edges
            .iter()
            .filter(|edge| edge.to_ref == target)
            .collect()
    }

    /// Returns the forward-direction edges for a historical/public source.
    pub fn outbound(&self, source: &str) -> Vec<&ProvenanceEdge> {
        self.edges
            .iter()
            .filter(|edge| edge.from_ref == source)
            .collect()
    }
}

/// Returns the content-addressed identity of this contract surface.
pub fn contract_identity() -> Result<ContractIdentity, ChangeMonitorError> {
    foundation_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &serde_json::json!({
            "observation": schemars::schema_for!(ChangeObservation),
            "snapshot": schemars::schema_for!(ChangeMonitorSnapshot),
            "anchor_candidate": schemars::schema_for!(AnchorCandidate),
            "provenance_view": schemars::schema_for!(ChangeProvenanceView),
        }),
    )
    .map_err(ChangeMonitorError::Foundation)
}
