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
    #[error("{field} exceeds its documented character ceiling")]
    TextTooLong { field: &'static str },
    #[error("epistemic input has no records")]
    EmptyInput,
    #[error("{field} carries {count} entries, above its admitted ceiling of {max}")]
    TooManyEntries {
        field: &'static str,
        count: usize,
        max: usize,
    },
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
    #[error("supersession lineage is cyclic: {}", handles.iter().map(ArtifactId::as_str).collect::<Vec<_>>().join(", "))]
    SupersessionCycle { handles: Vec<ArtifactId> },
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

/// Validates caller-supplied text and bounds it by an admitted ceiling.
///
/// The blank and control-character rules are the resolver's own; the ceiling is
/// not invented here. It is taken from the owner crate `eliot_epistemic_contracts`,
/// whose `error` module owns every variable-length bound for this domain
/// (`MAX_SHORT_TEXT` / `MAX_STATEMENT_TEXT`) and applies the same two constants to
/// the same shapes in its own `PositionRequest` and admitted-record contracts.
/// Without this bound a direct library caller could present unbounded
/// caller text; the wire boundary is not the only protection.
fn text(value: &str, field: &'static str, max: usize) -> Result<(), EpistemicError> {
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
        text(self.subject.as_str(), "record.subject", MAX_SHORT_TEXT)?;
        text(self.scope.as_str(), "record.scope", MAX_SHORT_TEXT)?;
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
        if let Some(note) = &self.note {
            text(note, "record.note", MAX_STATEMENT_TEXT)?;
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
    /// Validates the admitted read set before any resolution work begins.
    ///
    /// A supersession graph that contains a cycle has no current record: every
    /// member of the cycle is named as a predecessor by another member, so the
    /// supersession union removes all of them at once. Left unchecked that
    /// collapse is indistinguishable from an unobserved source, which is why it
    /// is refused here as [`EpistemicError::SupersessionCycle`] instead of
    /// reaching [`crate::resolve`] as ordinary absence. The refusal happens at
    /// this boundary, so no evidence is destroyed: [`crate::resolve`] derives
    /// no position and drops no provenance for a request it never admits.
    ///
    /// The text, record and edge ceilings are established here, before the
    /// handle index is built, so this method is the protection for a direct
    /// library caller and not merely a second check behind a wire boundary.
    pub fn validate(&self) -> Result<(), EpistemicError> {
        text(self.question.as_str(), "question", MAX_STATEMENT_TEXT)?;
        text(self.scope.as_str(), "scope", MAX_SHORT_TEXT)?;
        self.state_fence
            .validate()
            .map_err(|_| EpistemicError::InvalidFence)?;
        if self.records.is_empty() {
            return Err(EpistemicError::EmptyInput);
        }
        // The read set and every supersession edge are bounded by the ceiling the
        // owner crate admits for one request's records and supersession links, so
        // the index and the lineage walk below are sized by an admitted limit
        // rather than by whatever a direct library caller presented. This runs
        // before the index is built, as the validation boundary requires.
        if self.records.len() > MAX_HANDLES {
            return Err(EpistemicError::TooManyEntries {
                field: "records",
                count: self.records.len(),
                max: MAX_HANDLES,
            });
        }
        if let Some(record) = self
            .records
            .iter()
            .find(|record| record.supersedes.len() > MAX_HANDLES)
        {
            return Err(EpistemicError::TooManyEntries {
                field: "record.supersedes",
                count: record.supersedes.len(),
                max: MAX_HANDLES,
            });
        }
        // Unique handles are established first, because the lineage walk below
        // needs exactly one record per handle to be well defined.
        let mut by_handle: BTreeMap<&ArtifactId, &EpistemicRecord> = BTreeMap::new();
        for record in &self.records {
            if by_handle.insert(&record.handle, record).is_some() {
                return Err(EpistemicError::DuplicateHandle(record.handle.clone()));
            }
            record.validate(self.scope.as_str(), &self.state_fence)?;
        }
        // Every predecessor must name an admitted record in the same read set.
        // The index supplies the edges in handle order, not presentation order.
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

/// Walks the admitted supersession graph and refuses a cycle.
///
/// The walk is a loop over explicit stacks rather than a recursion, so caller
/// depth is bounded by the admitted read set and never by the call stack.
///
/// Nodes are visited in handle order and each node's predecessors in handle
/// order, so the walk depends only on the admitted set: a cycle is reported
/// identically for every permutation of the same records. No input order,
/// lexical handle or recency picks a winner either, because a cycle is refused
/// whole instead of having one member chosen to survive. The reported handles
/// are the cycle itself, sorted and bounded by the admitted handle ceiling so
/// the diagnostic cannot be steered into an unbounded string.
fn reject_supersession_cycle(
    edges: &BTreeMap<&ArtifactId, Vec<&ArtifactId>>,
) -> Result<(), EpistemicError> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Colour {
        /// Not yet reached.
        White,
        /// On the current chain; reaching one again closes a cycle.
        Grey,
        /// Fully explored; reaching one again cannot close a cycle.
        Black,
    }
    let mut colour: BTreeMap<&ArtifactId, Colour> = edges
        .keys()
        .map(|handle| (*handle, Colour::White))
        .collect();
    for start in edges.keys().copied() {
        if colour.get(start) != Some(&Colour::White) {
            continue;
        }
        // `path` is the current chain and `cursors[depth]` the next predecessor
        // index to try within `path[depth]`. The walk ends when the last node
        // is popped, which leaves `path` empty and `last()` returning `None`.
        let mut path: Vec<&ArtifactId> = vec![start];
        let mut cursors: Vec<usize> = vec![0];
        colour.insert(start, Colour::Grey);
        while let Some(&current) = path.last() {
            let depth = path.len() - 1;
            let successors: &[&ArtifactId] = edges.get(current).map_or(&[][..], Vec::as_slice);
            let Some(&next) = successors.get(cursors[depth]) else {
                colour.insert(current, Colour::Black);
                path.pop();
                cursors.pop();
                continue;
            };
            cursors[depth] += 1;
            // An absent entry is an unvisited one: every admitted handle is
            // seeded `White`, and every predecessor was resolved against the
            // same index before this walk, so no edge leaves the node set.
            match colour.get(next).copied().unwrap_or(Colour::White) {
                Colour::Grey => {
                    // `next` is already on this chain, so the chain from its
                    // position onward is the cycle. `next` is Grey only while it
                    // is on `path`, so the skip always stops and the reported
                    // handles are the cycle itself, never a prefix of it.
                    let mut involved: Vec<ArtifactId> = path
                        .iter()
                        .copied()
                        .skip_while(|handle| *handle != next)
                        .cloned()
                        .collect();
                    involved.sort();
                    involved.truncate(MAX_HANDLES);
                    return Err(EpistemicError::SupersessionCycle { handles: involved });
                }
                Colour::Black => {}
                Colour::White => {
                    colour.insert(next, Colour::Grey);
                    path.push(next);
                    cursors.push(0);
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
