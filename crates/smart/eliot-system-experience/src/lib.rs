//! The canonical owner for system-experience evidence.
//!
//! Experiences are admitted as immutable evidence records.  Interpretation,
//! lifecycle changes, and graph edges are separate append-only events; no
//! retrieval operation can rewrite a record or promote it into a claim.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use eliot_contracts::ArtifactId;
use eliot_evidence::{
    EpistemicStatus, EvidenceError, ExperienceRecord, LifecycleState, MemoryLifecycleTransition,
    RelationRecord, evidence_shape_digest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.smart.system_experience";
pub const CONTRACT_VERSION: &str = "1.0.0";
const MAX_QUERY_RESULTS: usize = 128;

/// An immutable event retained by the owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperienceEvent {
    /// The original record was admitted.
    Admitted,
    /// A governed lifecycle transition was applied.
    LifecycleChanged,
    /// A typed graph relation was admitted.
    RelationAdded,
}

/// Append-only history for an experience or relation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperienceHistoryEntry {
    pub sequence: u64,
    pub subject: ArtifactId,
    pub event: ExperienceEvent,
    pub reason: String,
}

/// Criteria for bounded system-experience retrieval.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExperienceQuery {
    pub scope: Option<String>,
    pub task_id: Option<eliot_contracts::TaskId>,
    pub lifecycle: Option<LifecycleState>,
    pub statuses: Vec<EpistemicStatus>,
    pub terms: Vec<String>,
    pub limit: usize,
}

/// A stable, bounded view returned by a query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperienceMatch {
    pub record: ExperienceRecord,
    pub rank: usize,
}

/// Current owner snapshot, suitable for rebuilding a derived index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperienceSnapshot {
    pub revision: u64,
    pub experiences: Vec<ExperienceRecord>,
    pub relations: Vec<RelationRecord>,
    pub digest: String,
}

/// Receipt for successful first admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionReceipt {
    pub experience_id: ArtifactId,
    pub revision: u64,
    pub duplicate: bool,
}

#[derive(Debug, Error)]
pub enum ExperienceError {
    #[error("evidence contract rejected the record: {0}")]
    Evidence(#[from] EvidenceError),
    #[error("experience already exists: {0}")]
    AlreadyExists(ArtifactId),
    #[error("experience not found: {0}")]
    NotFound(ArtifactId),
    #[error("relation endpoint is not an admitted experience: {0}")]
    UnknownEndpoint(ArtifactId),
    #[error("relation already exists: {0}")]
    RelationAlreadyExists(ArtifactId),
    #[error(
        "transition does not match the current lifecycle of {record}: expected {expected}, got {actual}"
    )]
    StaleTransition {
        record: ArtifactId,
        expected: LifecycleState,
        actual: LifecycleState,
    },
    #[error("owner state is unavailable")]
    Unavailable,
    #[error("owner revision overflow")]
    RevisionOverflow,
}

#[derive(Clone, Default)]
struct State {
    revision: u64,
    experiences: BTreeMap<ArtifactId, ExperienceRecord>,
    relations: BTreeMap<ArtifactId, RelationRecord>,
    history: Vec<ExperienceHistoryEntry>,
}

/// Thread-safe semantic owner of system-experience evidence.
#[derive(Clone, Default)]
pub struct SystemExperienceOwner {
    state: Arc<Mutex<State>>,
}

impl SystemExperienceOwner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates and admits one immutable experience. Admission is idempotent
    /// for the exact same serialized record and rejects conflicting reuse of
    /// the identity.
    pub fn admit(&self, record: ExperienceRecord) -> Result<AdmissionReceipt, ExperienceError> {
        record.validate()?;
        let id = record.experience_id.clone();
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExperienceError::Unavailable)?;
        if let Some(existing) = state.experiences.get(&id) {
            if existing == &record {
                return Ok(AdmissionReceipt {
                    experience_id: id,
                    revision: state.revision,
                    duplicate: true,
                });
            }
            return Err(ExperienceError::AlreadyExists(id));
        }
        let revision = next_revision(&mut state)?;
        state.experiences.insert(id.clone(), record);
        state.history.push(ExperienceHistoryEntry {
            sequence: revision,
            subject: id.clone(),
            event: ExperienceEvent::Admitted,
            reason: "initial_admission".to_owned(),
        });
        Ok(AdmissionReceipt {
            experience_id: id,
            revision,
            duplicate: false,
        })
    }

    /// Alias emphasizing that capture never implies promotion or assertion.
    pub fn capture(&self, record: ExperienceRecord) -> Result<AdmissionReceipt, ExperienceError> {
        self.admit(record)
    }

    pub fn experience(&self, id: &ArtifactId) -> Result<ExperienceRecord, ExperienceError> {
        self.state
            .lock()
            .map_err(|_| ExperienceError::Unavailable)?
            .experiences
            .get(id)
            .cloned()
            .ok_or_else(|| ExperienceError::NotFound(id.clone()))
    }

    /// Applies a forward-only, fenced lifecycle transition and records it.
    pub fn transition(
        &self,
        transition: MemoryLifecycleTransition,
    ) -> Result<ExperienceRecord, ExperienceError> {
        transition.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExperienceError::Unavailable)?;
        let current = state
            .experiences
            .get(&transition.record_id)
            .ok_or_else(|| ExperienceError::NotFound(transition.record_id.clone()))?;
        if current.lifecycle != transition.from {
            return Err(ExperienceError::StaleTransition {
                record: transition.record_id.clone(),
                expected: current.lifecycle,
                actual: transition.from,
            });
        }
        let mut updated = current.clone();
        updated.lifecycle = transition.to;
        state
            .experiences
            .insert(transition.record_id.clone(), updated.clone());
        let sequence = next_revision(&mut state)?;
        state.history.push(ExperienceHistoryEntry {
            sequence,
            subject: transition.record_id,
            event: ExperienceEvent::LifecycleChanged,
            reason: transition.reason,
        });
        Ok(updated)
    }

    /// Adds a validated graph edge only after both endpoints are known.
    pub fn add_relation(&self, relation: RelationRecord) -> Result<(), ExperienceError> {
        relation.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExperienceError::Unavailable)?;
        if !state.experiences.contains_key(&relation.from) {
            return Err(ExperienceError::UnknownEndpoint(relation.from));
        }
        if !state.experiences.contains_key(&relation.to) {
            return Err(ExperienceError::UnknownEndpoint(relation.to));
        }
        if state.relations.contains_key(&relation.relation_id) {
            return Err(ExperienceError::RelationAlreadyExists(relation.relation_id));
        }
        let id = relation.relation_id.clone();
        state.relations.insert(id.clone(), relation);
        let sequence = next_revision(&mut state)?;
        state.history.push(ExperienceHistoryEntry {
            sequence,
            subject: id,
            event: ExperienceEvent::RelationAdded,
            reason: "relation_admission".to_owned(),
        });
        Ok(())
    }

    pub fn relation(&self, id: &ArtifactId) -> Result<RelationRecord, ExperienceError> {
        self.state
            .lock()
            .map_err(|_| ExperienceError::Unavailable)?
            .relations
            .get(id)
            .cloned()
            .ok_or_else(|| ExperienceError::NotFound(id.clone()))
    }

    /// Returns deterministic, bounded results without changing owner state.
    pub fn query(&self, query: &ExperienceQuery) -> Result<Vec<ExperienceMatch>, ExperienceError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ExperienceError::Unavailable)?;
        let limit = if query.limit == 0 {
            MAX_QUERY_RESULTS
        } else {
            query.limit.min(MAX_QUERY_RESULTS)
        };
        let mut matches = state
            .experiences
            .values()
            .filter(|record| {
                query
                    .scope
                    .as_ref()
                    .is_none_or(|scope| &record.evidence.provenance.scope == scope)
            })
            .filter(|record| {
                query
                    .task_id
                    .as_ref()
                    .is_none_or(|task| record.task_id.as_ref() == Some(task))
            })
            .filter(|record| {
                query
                    .lifecycle
                    .is_none_or(|lifecycle| record.lifecycle == lifecycle)
            })
            .filter(|record| {
                query.statuses.is_empty() || query.statuses.contains(&record.evidence.status)
            })
            .filter(|record| query.terms.iter().all(|term| contains_term(record, term)))
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| left.experience_id.cmp(&right.experience_id));
        Ok(matches
            .into_iter()
            .take(limit)
            .enumerate()
            .map(|(rank, record)| ExperienceMatch { record, rank })
            .collect())
    }

    pub fn snapshot(&self) -> Result<ExperienceSnapshot, ExperienceError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ExperienceError::Unavailable)?;
        let experiences = state.experiences.values().cloned().collect::<Vec<_>>();
        let relations = state.relations.values().cloned().collect::<Vec<_>>();
        let digest = evidence_shape_digest(&(&state.revision, &experiences, &relations))?;
        Ok(ExperienceSnapshot {
            revision: state.revision,
            experiences,
            relations,
            digest,
        })
    }

    pub fn history(&self) -> Result<Vec<ExperienceHistoryEntry>, ExperienceError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| ExperienceError::Unavailable)?
            .history
            .clone())
    }
}

fn next_revision(state: &mut State) -> Result<u64, ExperienceError> {
    state.revision = state
        .revision
        .checked_add(1)
        .ok_or(ExperienceError::RevisionOverflow)?;
    Ok(state.revision)
}

fn contains_term(record: &ExperienceRecord, term: &str) -> bool {
    let needle = term.trim().to_lowercase();
    !needle.is_empty()
        && [
            record.episode.as_str(),
            record.action.as_str(),
            record.outcome.as_str(),
        ]
        .iter()
        .any(|text| text.to_lowercase().contains(&needle))
}
