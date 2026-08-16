//! Deterministic ownership boundary for epistemic position and provenance.
//!
//! The resolver never manufactures truth and never mutates a source record. It
//! evaluates an admitted, fenced read set and returns a forward-rebuildable
//! position with every decision-bearing handle and uncertainty preserved.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ContractVersion, StateFence};
use eliot_evidence::{Assertability, EpistemicStatus, EvidenceEnvelope, EvidenceFreshness};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.smart.epistemic";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum EpistemicError {
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("epistemic input has no records")]
    EmptyInput,
    #[error("epistemic input contains duplicate handle {0}")]
    DuplicateHandle(ArtifactId),
    #[error("record {handle} has a scope different from the requested scope")]
    ScopeMismatch { handle: ArtifactId },
    #[error("record {handle} is not compatible with the requested state fence")]
    FenceMismatch { handle: ArtifactId },
    #[error("requested state fence is invalid")]
    InvalidFence,
    #[error("record {handle} has invalid evidence: {reason}")]
    InvalidEvidence { handle: ArtifactId, reason: String },
    #[error("inquiry {0} must be non-blank")]
    InvalidInquiry(String),
}

fn text(value: &str, field: &'static str) -> Result<(), EpistemicError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(EpistemicError::InvalidText { field })
    } else {
        Ok(())
    }
}

/// The resolver's position algebra. `Assumed` is deliberately a position
/// state, not a promotion of the underlying `EpistemicStatus` vocabulary.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PositionState {
    Observed,
    Supported,
    Assumed,
    Conflicted,
    Stale,
    Unknown,
}

/// One immutable candidate supplied by the canonical semantic owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpistemicRecord {
    pub handle: ArtifactId,
    pub subject: String,
    pub scope: String,
    pub evidence: EvidenceEnvelope,
    /// Exact predecessors retained even when this record is current.
    pub supersedes: Vec<ArtifactId>,
    /// Explicit inquiry or interpretation note; never treated as evidence.
    pub note: Option<String>,
}

impl EpistemicRecord {
    pub fn validate(
        &self,
        requested_scope: &str,
        fence: &StateFence,
    ) -> Result<(), EpistemicError> {
        text(self.subject.as_str(), "record.subject")?;
        text(self.scope.as_str(), "record.scope")?;
        if self.scope != requested_scope {
            return Err(EpistemicError::ScopeMismatch {
                handle: self.handle.clone(),
            });
        }
        if !self.evidence.state_fence.is_compatible_with(fence) {
            return Err(EpistemicError::FenceMismatch {
                handle: self.handle.clone(),
            });
        }
        self.evidence
            .validate()
            .map_err(|source| EpistemicError::InvalidEvidence {
                handle: self.handle.clone(),
                reason: source.to_string(),
            })?;
        if let Some(note) = &self.note {
            text(note, "record.note")?;
        }
        Ok(())
    }
}

/// A bounded resolver request. Records must already be admitted by the
/// canonical owner; this type only performs deterministic semantic resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PositionRequest {
    pub question: String,
    pub scope: String,
    pub state_fence: StateFence,
    pub records: Vec<EpistemicRecord>,
}

impl PositionRequest {
    pub fn validate(&self) -> Result<(), EpistemicError> {
        text(self.question.as_str(), "question")?;
        text(self.scope.as_str(), "scope")?;
        self.state_fence
            .validate()
            .map_err(|_| EpistemicError::InvalidFence)?;
        if self.records.is_empty() {
            return Err(EpistemicError::EmptyInput);
        }
        let mut handles = BTreeSet::new();
        for record in &self.records {
            if !handles.insert(record.handle.clone()) {
                return Err(EpistemicError::DuplicateHandle(record.handle.clone()));
            }
            record.validate(self.scope.as_str(), &self.state_fence)?;
        }
        Ok(())
    }
}

/// Exact provenance closure for the returned position.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceView {
    pub record_handles: Vec<ArtifactId>,
    pub source_ids: Vec<String>,
    pub raw_handles: Vec<String>,
    pub revisions: Vec<String>,
    pub mixed_sources: bool,
    pub assertability: Assertability,
}

/// The best currently supported position, with rivals and inquiry preserved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurrentEpistemicPosition {
    pub question: String,
    pub scope: String,
    pub state_fence: StateFence,
    pub state: PositionState,
    pub direct_observations: Vec<ArtifactId>,
    pub supporting_records: Vec<ArtifactId>,
    pub rival_records: Vec<ArtifactId>,
    pub stale_records: Vec<ArtifactId>,
    pub superseded_records: Vec<ArtifactId>,
    pub unknowns: Vec<String>,
    pub required_inquiry: Vec<String>,
    pub provenance: ProvenanceView,
}

/// Resolve one question without ranking by prose, vote count, or model output.
pub fn resolve(request: &PositionRequest) -> Result<CurrentEpistemicPosition, EpistemicError> {
    request.validate()?;
    let mut direct = BTreeSet::new();
    let mut supporting = BTreeSet::new();
    let mut rivals = BTreeSet::new();
    let mut stale = BTreeSet::new();
    let mut superseded = BTreeSet::new();
    let mut unknowns = BTreeSet::new();
    let mut inquiries = BTreeSet::new();
    let mut current = Vec::new();

    for record in &request.records {
        if record.evidence.freshness == EvidenceFreshness::Stale {
            stale.insert(record.handle.clone());
            inquiries.insert(format!("revalidate {}", record.handle));
            continue;
        }
        match record.evidence.status {
            EpistemicStatus::Observed => {
                direct.insert(record.handle.clone());
                current.push(record);
            }
            EpistemicStatus::Supported | EpistemicStatus::Verified => {
                supporting.insert(record.handle.clone());
                current.push(record);
            }
            EpistemicStatus::Contested => {
                rivals.insert(record.handle.clone());
                current.push(record);
            }
            EpistemicStatus::Stale => {
                stale.insert(record.handle.clone());
                inquiries.insert(format!("revalidate {}", record.handle));
            }
            EpistemicStatus::Superseded => {
                superseded.insert(record.handle.clone());
            }
            EpistemicStatus::Rejected => {
                rivals.insert(record.handle.clone());
                inquiries.insert(format!("reassess rejected {}", record.handle));
            }
            EpistemicStatus::Unknown => {
                unknowns.insert(record.subject.clone());
                inquiries.insert(format!("obtain evidence for {}", record.subject));
            }
        }
        if matches!(
            record.evidence.freshness,
            EvidenceFreshness::Stale | EvidenceFreshness::Unknown
        ) {
            stale.insert(record.handle.clone());
            inquiries.insert(format!("establish freshness for {}", record.handle));
        }
        if let Some(note) = &record.note {
            inquiries.insert(note.clone());
        }
    }
    if current.is_empty() {
        unknowns.insert(request.question.clone());
    }
    let position_state = if !rivals.is_empty() {
        PositionState::Conflicted
    } else if !supporting.is_empty() {
        PositionState::Supported
    } else if !direct.is_empty() {
        PositionState::Observed
    } else if !stale.is_empty() {
        PositionState::Stale
    } else {
        PositionState::Unknown
    };
    if matches!(
        position_state,
        PositionState::Conflicted | PositionState::Stale | PositionState::Unknown
    ) {
        inquiries.insert("perform the cheapest discriminative inquiry".to_owned());
    }
    let provenance = provenance_for(
        &request.records,
        &direct,
        &supporting,
        &rivals,
        &stale,
        &superseded,
    );
    Ok(CurrentEpistemicPosition {
        question: request.question.clone(),
        scope: request.scope.clone(),
        state_fence: request.state_fence.clone(),
        state: position_state,
        direct_observations: direct.into_iter().collect(),
        supporting_records: supporting.into_iter().collect(),
        rival_records: rivals.into_iter().collect(),
        stale_records: stale.into_iter().collect(),
        superseded_records: superseded.into_iter().collect(),
        unknowns: unknowns.into_iter().collect(),
        required_inquiry: inquiries.into_iter().collect(),
        provenance,
    })
}

fn provenance_for(
    records: &[EpistemicRecord],
    direct: &BTreeSet<ArtifactId>,
    supporting: &BTreeSet<ArtifactId>,
    rivals: &BTreeSet<ArtifactId>,
    stale: &BTreeSet<ArtifactId>,
    superseded: &BTreeSet<ArtifactId>,
) -> ProvenanceView {
    let selected: BTreeSet<_> = direct
        .iter()
        .chain(supporting)
        .chain(rivals)
        .chain(stale)
        .chain(superseded)
        .cloned()
        .collect();
    let mut sources = BTreeSet::new();
    let mut raw = BTreeSet::new();
    let mut revisions = BTreeSet::new();
    let mut assertability = Assertability::Assertable;
    for record in records.iter().filter(|r| selected.contains(&r.handle)) {
        sources.insert(record.evidence.provenance.source_id.to_string());
        if let Some(value) = &record.evidence.provenance.raw_handle {
            raw.insert(value.clone());
        }
        if let Some(value) = &record.evidence.provenance.revision {
            revisions.insert(value.clone());
        }
        assertability = lowest_assertability(assertability, record.evidence.assertability);
    }
    let mixed_sources = sources_len(records, &selected) > 1;
    ProvenanceView {
        record_handles: selected.into_iter().collect(),
        source_ids: sources.into_iter().collect(),
        raw_handles: raw.into_iter().collect(),
        revisions: revisions.into_iter().collect(),
        mixed_sources,
        assertability,
    }
}

fn sources_len(records: &[EpistemicRecord], selected: &BTreeSet<ArtifactId>) -> usize {
    records
        .iter()
        .filter(|r| selected.contains(&r.handle))
        .map(|r| r.evidence.provenance.source_id.clone())
        .collect::<BTreeSet<_>>()
        .len()
}

fn lowest_assertability(left: Assertability, right: Assertability) -> Assertability {
    match (left, right) {
        (Assertability::AbstainOrFence, _) | (_, Assertability::AbstainOrFence) => {
            Assertability::AbstainOrFence
        }
        (Assertability::NonAssertableUnverified, _)
        | (_, Assertability::NonAssertableUnverified) => Assertability::NonAssertableUnverified,
        _ => Assertability::Assertable,
    }
}
