//! Rebuildable change observations and deterministic historical-anchor
//! resolution.
//!
//! ChangeMonitor is an observation/projection component.  It does not watch a
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
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

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
    fn from(error: eliot_agent_contracts::ContractError) -> Self {
        // Agent contract errors intentionally remain distinct at their own
        // surface; this projection exposes only a stable invalid-anchor class.
        match error {
            eliot_agent_contracts::ContractError::AmbiguousAnchor
            | eliot_agent_contracts::ContractError::UnusableAnchor
            | eliot_agent_contracts::ContractError::InvalidReference => Self::InvalidAnchor,
            _ => Self::InvalidAnchor,
        }
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

/// Immutable record held by the rebuildable ChangeMonitor projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedChangeRecord {
    /// Original observation.
    pub observation: ChangeObservation,
    /// Content digest for deterministic replay.
    pub observation_digest: String,
}

/// Rebuildable ChangeMonitor view.  It can be reconstructed from observation
/// records and does not supersede canonical source history.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeMonitorSnapshot {
    /// Immutable observation records by change identity.
    pub observations: Vec<ObservedChangeRecord>,
    /// Current resource projection by stable resource identity.
    pub current_resources: Vec<ResourceSnapshot>,
    /// Dependencies observed invalidated by any included change.
    pub invalidated_dependencies: Vec<String>,
}

/// In-memory rebuildable projection over immutable observations.
#[derive(Clone, Debug, Default)]
pub struct ChangeMonitor {
    observations: BTreeMap<String, ObservedChangeRecord>,
    current_resources: BTreeMap<String, ResourceSnapshot>,
    invalidated_dependencies: BTreeSet<String>,
}

impl ChangeMonitor {
    /// Rebuilds the monitor from canonical immutable observations.
    pub fn from_snapshot(snapshot: ChangeMonitorSnapshot) -> Result<Self, ChangeMonitorError> {
        let mut monitor = Self::default();
        for record in snapshot.observations {
            let observed = record.observation.clone();
            if observed.digest()? != record.observation_digest {
                return Err(ChangeMonitorError::IdentityConflict);
            }
            monitor.ingest(observed)?;
        }
        if monitor.snapshot().current_resources != snapshot.current_resources
            || monitor.snapshot().invalidated_dependencies != snapshot.invalidated_dependencies
        {
            return Err(ChangeMonitorError::IdentityConflict);
        }
        Ok(monitor)
    }

    /// Ingests one observation, treating an identical replay as idempotent.
    pub fn ingest(
        &mut self,
        observation: ChangeObservation,
    ) -> Result<ObservationAdmission, ChangeMonitorError> {
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
                acceptance_blocked: existing.observation.unknown_origin
                    && is_material_mutation(existing.observation.kind),
                invalidation_dependencies: existing
                    .observation
                    .invalidations
                    .iter()
                    .map(|item| item.dependency.clone())
                    .collect(),
            });
        }
        let acceptance_blocked =
            observation.unknown_origin && is_material_mutation(observation.kind);
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
        Ok(ObservationAdmission {
            change_id,
            observation_digest: digest,
            disposition: IngestDisposition::Accepted,
            acceptance_blocked,
            invalidation_dependencies,
        })
    }

    /// Returns a deterministic snapshot suitable for rebuilding consumers.
    pub fn snapshot(&self) -> ChangeMonitorSnapshot {
        ChangeMonitorSnapshot {
            observations: self.observations.values().cloned().collect(),
            current_resources: self.current_resources.values().cloned().collect(),
            invalidated_dependencies: self.invalidated_dependencies.iter().cloned().collect(),
        }
    }

    /// Returns whether any unknown-origin material mutation blocks acceptance.
    pub fn has_unknown_material_change(&self) -> bool {
        self.observations.values().any(|record| {
            record.observation.unknown_origin && is_material_mutation(record.observation.kind)
        })
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

/// Deterministic resolver over immutable original identity and explicit
/// current candidates.
#[derive(Clone, Copy, Debug, Default)]
pub struct EvolvingAnchorResolver;

impl EvolvingAnchorResolver {
    /// Resolves one historical anchor without nearest-neighbour attachment.
    pub fn resolve(
        &self,
        original: &AnchorReference,
        candidates: &[AnchorCandidate],
        monitor: &ChangeMonitorSnapshot,
    ) -> Result<AnchorResolution, ChangeMonitorError> {
        original.validate().map_err(ChangeMonitorError::from)?;
        for candidate in candidates {
            candidate.validate()?;
        }
        let anchor_id = original.anchor_id.clone();
        let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
        let exact: Vec<&AnchorCandidate> = candidates
            .iter()
            .filter(|candidate| &candidate.reference == original)
            .collect();
        if exact.len() == 1 {
            return Ok(AnchorResolution {
                anchor_id,
                status: AnchorResolutionStatus::Exact,
                current_reference: Some(exact[0].reference.clone()),
                candidate_count,
            });
        }
        if exact.len() > 1 {
            return Ok(AnchorResolution {
                anchor_id,
                status: AnchorResolutionStatus::Ambiguous,
                current_reference: None,
                candidate_count,
            });
        }
        let same_target: Vec<&AnchorCandidate> = candidates
            .iter()
            .filter(|candidate| candidate.reference.target.id == original.target.id)
            .collect();
        if same_target.len() == 1 {
            let candidate = same_target[0];
            let same_location = candidate.reference.path == original.path
                && candidate.reference.symbol == original.symbol
                && candidate.reference.line_start == original.line_start
                && candidate.reference.line_end == original.line_end;
            return Ok(AnchorResolution {
                anchor_id,
                status: if same_location {
                    AnchorResolutionStatus::Modified
                } else {
                    AnchorResolutionStatus::Moved
                },
                current_reference: Some(candidate.reference.clone()),
                candidate_count,
            });
        }
        if same_target.len() > 1 {
            return Ok(AnchorResolution {
                anchor_id,
                status: AnchorResolutionStatus::Ambiguous,
                current_reference: None,
                candidate_count,
            });
        }
        let fingerprint_matches: Vec<&AnchorCandidate> = candidates
            .iter()
            .filter(|candidate| {
                candidate.reference.context_digest == original.context_digest
                    || candidate.content_digest.as_deref() == Some(original.context_digest.as_str())
                    || candidate.structural_digest.as_deref()
                        == Some(original.context_digest.as_str())
            })
            .collect();
        if fingerprint_matches.len() == 1 {
            return Ok(AnchorResolution {
                anchor_id,
                status: AnchorResolutionStatus::Moved,
                current_reference: Some(fingerprint_matches[0].reference.clone()),
                candidate_count,
            });
        }
        if fingerprint_matches.len() > 1 {
            return Ok(AnchorResolution {
                anchor_id,
                status: AnchorResolutionStatus::Ambiguous,
                current_reference: None,
                candidate_count,
            });
        }
        let historical_matches: Vec<&AnchorCandidate> = candidates
            .iter()
            .filter(|candidate| candidate.historical_range_match)
            .collect();
        let status = if historical_matches.len() == 1 {
            return Ok(AnchorResolution {
                anchor_id,
                status: AnchorResolutionStatus::Moved,
                current_reference: Some(historical_matches[0].reference.clone()),
                candidate_count,
            });
        } else if historical_matches.len() > 1 {
            AnchorResolutionStatus::Ambiguous
        } else if monitor.observations.iter().any(|record| {
            record.observation.kind == ChangeKind::Deleted
                && record.observation.resource_ref() == original.target.id.as_str()
        }) {
            AnchorResolutionStatus::Deleted
        } else if candidates.is_empty() {
            AnchorResolutionStatus::Unavailable
        } else {
            AnchorResolutionStatus::Stale
        };
        Ok(AnchorResolution {
            anchor_id,
            status,
            current_reference: None,
            candidate_count,
        })
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

/// Rebuildable bidirectional view consumed by CodeCortex and review surfaces.
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
