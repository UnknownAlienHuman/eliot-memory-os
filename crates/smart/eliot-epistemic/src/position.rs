//! Current Epistemic Position algebra: the resolver-owned position types.
//!
//! `PositionState`, `EpistemicRecord`, `PositionRequest`, `ProvenanceView`
//! and the local [`CurrentEpistemicPosition`] plus the shared
//! [`EpistemicError`] validation vocabulary. Wire types stay with
//! `eliot-epistemic-contracts`; this algebra is resolver policy over
//! admitted, fenced evidence, never a wire duplicate.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, StateFence};
use eliot_epistemic_contracts::{MAX_HANDLES, MAX_SHORT_TEXT, MAX_STATEMENT_TEXT};
use eliot_evidence::{Assertability, EvidenceEnvelope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum EpistemicError {
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("epistemic input has no records")]
    EmptyInput,
    #[error("epistemic input contains duplicate handle {0}")]
    DuplicateHandle(ArtifactId),
    #[error("record {handle} supersedes itself")]
    SelfSupersession { handle: ArtifactId },
    #[error("record {handle} contains duplicate predecessor {predecessor}")]
    DuplicatePredecessor {
        handle: ArtifactId,
        predecessor: ArtifactId,
    },
    #[error("record {handle} references missing predecessor {predecessor}")]
    MissingPredecessor {
        handle: ArtifactId,
        predecessor: ArtifactId,
    },
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
    #[error("{field} exceeds the maximum length")]
    TextTooLong { field: &'static str },
    #[error("{field} exceeds the maximum record count")]
    TooManyRecords { field: &'static str },
    #[error("{field} exceeds the maximum supersession edge count")]
    TooManyEdges { field: &'static str },
    #[error("supersession lineage contains a cycle over handles: {}", .handles.join(", "))]
    SupersessionCycle { handles: Vec<String> },
}

/// Validates non-blank, control-free text against the admitted character
/// ceiling, so a direct library caller is refused exactly as a wire caller is.
fn bounded_text(value: &str, field: &'static str, max: usize) -> Result<(), EpistemicError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(EpistemicError::InvalidText { field });
    }
    if value.chars().count() > max {
        return Err(EpistemicError::TextTooLong { field });
    }
    Ok(())
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
        bounded_text(self.subject.as_str(), "record.subject", MAX_SHORT_TEXT)?;
        bounded_text(self.scope.as_str(), "record.scope", MAX_SHORT_TEXT)?;
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
        let mut predecessors = BTreeSet::new();
        for predecessor in &self.supersedes {
            if predecessor == &self.handle {
                return Err(EpistemicError::SelfSupersession {
                    handle: self.handle.clone(),
                });
            }
            if !predecessors.insert(predecessor.clone()) {
                return Err(EpistemicError::DuplicatePredecessor {
                    handle: self.handle.clone(),
                    predecessor: predecessor.clone(),
                });
            }
        }
        if self.supersedes.len() > MAX_HANDLES {
            return Err(EpistemicError::TooManyEdges {
                field: "record.supersedes",
            });
        }
        if let Some(note) = &self.note {
            bounded_text(note, "record.note", MAX_STATEMENT_TEXT)?;
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
    /// Validates this request at the boundary, before any resolution work.
    ///
    /// Collection and text ceilings are established first, using the admitted
    /// contract limits, so a direct library caller is bounded before an index
    /// is built. Handles are then indexed once, predecessors are resolved
    /// against that index, and the supersession graph is walked iteratively:
    /// a cycle is a typed refusal naming the handles involved, never a silent
    /// collapse into ordinary absence.
    pub fn validate(&self) -> Result<(), EpistemicError> {
        bounded_text(self.question.as_str(), "question", MAX_STATEMENT_TEXT)?;
        bounded_text(self.scope.as_str(), "scope", MAX_SHORT_TEXT)?;
        self.state_fence
            .validate()
            .map_err(|_| EpistemicError::InvalidFence)?;
        if self.records.is_empty() {
            return Err(EpistemicError::EmptyInput);
        }
        if self.records.len() > MAX_HANDLES {
            return Err(EpistemicError::TooManyRecords {
                field: "request.records",
            });
        }
        if self
            .records
            .iter()
            .any(|r| r.supersedes.len() > MAX_HANDLES)
        {
            return Err(EpistemicError::TooManyEdges {
                field: "request.records",
            });
        }
        let mut by_handle: BTreeMap<&ArtifactId, &EpistemicRecord> = BTreeMap::new();
        for record in &self.records {
            if by_handle.insert(&record.handle, record).is_some() {
                return Err(EpistemicError::DuplicateHandle(record.handle.clone()));
            }
            record.validate(self.scope.as_str(), &self.state_fence)?;
        }
        // Every predecessor must name an admitted record in the same read set.
        let mut edges: BTreeMap<&ArtifactId, Vec<&ArtifactId>> = BTreeMap::new();
        for record in &self.records {
            let mut predecessors = Vec::with_capacity(record.supersedes.len());
            for predecessor in &record.supersedes {
                if !by_handle.contains_key(predecessor) {
                    return Err(EpistemicError::MissingPredecessor {
                        handle: record.handle.clone(),
                        predecessor: predecessor.clone(),
                    });
                }
                predecessors.push(predecessor);
            }
            // Visiting order is handle order, not presentation order, so the
            // walk cannot be steered by how the caller sorted the list.
            predecessors.sort();
            edges.insert(&record.handle, predecessors);
        }
        reject_supersession_cycle(&edges)?;
        Ok(())
    }
}

/// Walks the supersession graph iteratively and refuses a cycle.
///
/// Node order is the handle order of the index, and each node's edges are
/// visited in handle order, so the walk depends only on the admitted set. A
/// cycle is therefore reported the same way whatever order the caller supplied
/// its records or predecessors in: no input order, lexical handle, or recency
/// picks a winner, because a cycle here has no winner at all. The walk is a
/// loop over explicit stacks, never a recursion, so caller depth is bounded by
/// the admitted record ceiling rather than by the call stack.
fn reject_supersession_cycle(
    edges: &BTreeMap<&ArtifactId, Vec<&ArtifactId>>,
) -> Result<(), EpistemicError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Colour {
        White,
        Grey,
        Black,
    }
    let mut colour: BTreeMap<&ArtifactId, Colour> = edges
        .keys()
        .map(|handle| (*handle, Colour::White))
        .collect();
    for start in edges.keys().copied() {
        if colour.get(&start).copied() != Some(Colour::White) {
            continue;
        }
        // `path` is the current chain and `cursors[depth]` the next edge index
        // to try within `path[depth]`. Reaching a Grey node closes a cycle.
        let mut path: Vec<&ArtifactId> = vec![start];
        let mut cursors: Vec<usize> = vec![0];
        colour.insert(start, Colour::Grey);
        // The walk ends when the chain is exhausted, which is the `None` arm
        // popping the last node and the next iteration finding `path` empty.
        while let Some(&current) = path.last() {
            let depth = path.len() - 1;
            let successors = edges.get(current).map(Vec::as_slice).unwrap_or_default();
            match successors.get(cursors[depth]) {
                None => {
                    colour.insert(current, Colour::Black);
                    path.pop();
                    cursors.pop();
                }
                Some(&next) => {
                    cursors[depth] += 1;
                    match colour.get(&next).copied() {
                        Some(Colour::Grey) => {
                            let cycle_start = path
                                .iter()
                                .position(|candidate| *candidate == next)
                                .unwrap_or(0);
                            let mut involved: Vec<String> = path[cycle_start..]
                                .iter()
                                .map(|handle| handle.as_str().to_owned())
                                .collect();
                            // Bounded by the admitted ceiling, and reported in
                            // handle order so the diagnostic is the same for
                            // every permutation of the same admitted set.
                            involved.sort();
                            involved.truncate(MAX_HANDLES);
                            return Err(EpistemicError::SupersessionCycle { handles: involved });
                        }
                        Some(Colour::Black) => {}
                        _ => {
                            colour.insert(next, Colour::Grey);
                            path.push(next);
                            cursors.push(0);
                        }
                    }
                }
            }
        }
    }
    Ok(())
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
