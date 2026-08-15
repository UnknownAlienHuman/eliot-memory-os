//! The semantic owner of ELIOT's canonical memory plane.
//!
//! This crate intentionally does not expose a database or a query language.  It
//! owns the admission invariants that must hold regardless of the storage
//! backend: capture is loss-tolerant, history is append-only, derived views are
//! rebuildable, and retrieval cannot silently promote or reinforce a record.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.smart.memory";
pub const CONTRACT_VERSION: &str = "1.0.0";
const MAX_TEXT_BYTES: usize = 1_048_576;
const MAX_RESULTS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MemoryId(String);

impl MemoryId {
    pub fn new(value: impl Into<String>) -> Result<Self, MemoryError> {
        let value = value.into();
        validate_text(&value, "memory_id")?;
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MemoryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationHint {
    Observation,
    Decision,
    Failure,
    Outcome,
    Unknown,
    ReuseCandidate,
    Auto,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    ObservationCandidate,
    Decision,
    Failure,
    Outcome,
    Unknown,
    Experience,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicStatus {
    Observed,
    Supported,
    Verified,
    Contested,
    Stale,
    Superseded,
    Rejected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Active,
    Dormant,
    Suppressed,
    Quarantined,
    Archived,
    Forgotten,
    Superseded,
}

impl Lifecycle {
    fn can_transition_to(self, next: Self) -> bool {
        if self == next {
            return false;
        }
        matches!(
            (self, next),
            (
                Self::Active,
                Self::Dormant
                    | Self::Suppressed
                    | Self::Quarantined
                    | Self::Archived
                    | Self::Superseded
            ) | (
                Self::Dormant,
                Self::Active
                    | Self::Suppressed
                    | Self::Quarantined
                    | Self::Archived
                    | Self::Superseded
            ) | (
                Self::Suppressed,
                Self::Active | Self::Dormant | Self::Quarantined | Self::Archived
            ) | (
                Self::Quarantined,
                Self::Active | Self::Suppressed | Self::Archived
            ) | (Self::Archived, Self::Active | Self::Forgotten)
                | (Self::Superseded, Self::Archived)
                | (Self::Forgotten, Self::Archived)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CueKind {
    FilePath,
    Symbol,
    ErrorSignature,
    Command,
    Service,
    TaskClass,
    Concept,
    Commitment,
    Problem,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Cue {
    pub kind: CueKind,
    pub value: String,
    pub exact: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationInput {
    pub scope: String,
    pub session: Option<String>,
    pub task: Option<String>,
    pub source: String,
    pub content: String,
    pub hint: ObservationHint,
    pub affected_resources: Vec<String>,
    pub expected_reuse_note: Option<String>,
    pub cues: Vec<Cue>,
    pub support: Vec<String>,
    pub counterevidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub id: MemoryId,
    pub revision: u64,
    pub scope: String,
    pub session: Option<String>,
    pub task: Option<String>,
    pub source: String,
    pub content: String,
    pub kind: RecordKind,
    pub status: EpistemicStatus,
    pub lifecycle: Lifecycle,
    pub support: Vec<String>,
    pub counterevidence: Vec<String>,
    pub cues: Vec<Cue>,
    pub lineage: Vec<MemoryId>,
    pub influence_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevisionEvent {
    pub record_id: MemoryId,
    pub revision: u64,
    pub kind: RevisionKind,
    pub reason: String,
    pub source: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionKind {
    Captured,
    LifecycleChanged,
    Superseded,
    InfluenceRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetrievalRequest {
    pub scope: String,
    pub cues: Vec<Cue>,
    pub session: Option<String>,
    pub limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetrievedMemory {
    pub record: MemoryRecord,
    pub match_kind: MatchKind,
    pub rank: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    NegativeExact,
    Exact,
    Prefix,
    Signature,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnderstandingView {
    pub scope: String,
    pub revision: u64,
    pub records: Vec<MemoryId>,
    pub negative_records: Vec<MemoryId>,
    pub unknowns: Vec<MemoryId>,
    pub state_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureReceipt {
    pub id: MemoryId,
    pub revision: u64,
    pub status: EpistemicStatus,
    pub cold: bool,
}

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("{field} is blank or contains a control character")]
    InvalidText { field: &'static str },
    #[error("{field} exceeds the memory payload limit")]
    Oversized { field: &'static str },
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("record not found: {0}")]
    NotFound(MemoryId),
    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    InvalidLifecycle { from: Lifecycle, to: Lifecycle },
    #[error("verified status requires support and a verification source")]
    VerificationNeedsEvidence,
    #[error("record is not eligible for influence")]
    InfluenceDenied,
    #[error("memory state is unavailable")]
    Unavailable,
    #[error("serialization failure: {0}")]
    Serialization(String),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), MemoryError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(MemoryError::InvalidText { field });
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(MemoryError::Oversized { field });
    }
    Ok(())
}

fn unique_strings(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}
fn normalize_cues(cues: &mut Vec<Cue>) -> Result<(), MemoryError> {
    for cue in cues.iter_mut() {
        validate_text(&cue.value, "cue.value")?;
        cue.value = cue.value.trim().to_owned();
    }
    cues.sort();
    cues.dedup();
    Ok(())
}

#[derive(Clone, Default)]
struct State {
    next_revision: u64,
    records: BTreeMap<MemoryId, MemoryRecord>,
    history: Vec<RevisionEvent>,
    delivered: BTreeMap<String, BTreeSet<MemoryId>>,
}

/// Thread-safe canonical memory owner.  All mutations pass through this type;
/// callers receive snapshots and receipts, never mutable record storage.
#[derive(Clone, Default)]
pub struct MemoryPlane {
    state: Arc<Mutex<State>>,
}

impl MemoryPlane {
    pub fn new() -> Self {
        Self::default()
    }

    /// Captures safe material even when classification or reuse metadata is weak.
    pub fn capture(&self, mut input: ObservationInput) -> Result<CaptureReceipt, MemoryError> {
        validate_text(&input.scope, "scope")?;
        validate_text(&input.source, "source")?;
        validate_text(&input.content, "content")?;
        for value in &input.affected_resources {
            validate_text(value, "affected_resource")?;
        }
        unique_strings(&mut input.affected_resources);
        unique_strings(&mut input.support);
        unique_strings(&mut input.counterevidence);
        normalize_cues(&mut input.cues)?;
        let (kind, status) = classify(&input);
        let mut state = self.state.lock().map_err(|_| MemoryError::Unavailable)?;
        state.next_revision = state
            .next_revision
            .checked_add(1)
            .ok_or(MemoryError::Oversized { field: "revision" })?;
        let revision = state.next_revision;
        let id = MemoryId::new(format!(
            "mem-{revision:016x}-{}",
            stable_digest(input.content.as_bytes())
        ))?;
        let mut cues = input.cues;
        for resource in input.affected_resources {
            cues.push(Cue {
                kind: CueKind::FilePath,
                value: resource,
                exact: true,
            });
        }
        normalize_cues(&mut cues)?;
        let record = MemoryRecord {
            id: id.clone(),
            revision,
            scope: input.scope,
            session: input.session,
            task: input.task,
            source: input.source.clone(),
            content: input.content,
            kind,
            status,
            lifecycle: Lifecycle::Active,
            support: input.support,
            counterevidence: input.counterevidence,
            cues,
            lineage: Vec::new(),
            influence_allowed: false,
        };
        let cold = record.cues.is_empty()
            || matches!(
                record.status,
                EpistemicStatus::Unknown | EpistemicStatus::Rejected
            );
        state.records.insert(id.clone(), record);
        state.history.push(RevisionEvent {
            record_id: id.clone(),
            revision,
            kind: RevisionKind::Captured,
            reason: "capture_first".to_owned(),
            source: input.source,
        });
        Ok(CaptureReceipt {
            id,
            revision,
            status,
            cold,
        })
    }

    pub fn record(&self, id: &MemoryId) -> Result<MemoryRecord, MemoryError> {
        self.state
            .lock()
            .map_err(|_| MemoryError::Unavailable)?
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| MemoryError::NotFound(id.clone()))
    }

    /// Applies a governed status transition; retrieval and repetition cannot call this.
    pub fn revise_status(
        &self,
        id: &MemoryId,
        status: EpistemicStatus,
        reason: String,
        source: String,
    ) -> Result<MemoryRecord, MemoryError> {
        validate_text(&reason, "reason")?;
        validate_text(&source, "source")?;
        let mut state = self.state.lock().map_err(|_| MemoryError::Unavailable)?;
        let updated = {
            let record = state
                .records
                .get_mut(id)
                .ok_or_else(|| MemoryError::NotFound(id.clone()))?;
            if status == EpistemicStatus::Verified
                && (record.support.is_empty() || source.trim().is_empty())
            {
                return Err(MemoryError::VerificationNeedsEvidence);
            }
            if matches!(
                record.status,
                EpistemicStatus::Rejected | EpistemicStatus::Superseded
            ) && status != record.status
            {
                return Err(MemoryError::InfluenceDenied);
            }
            record.status = status;
            record.clone()
        };
        state.history.push(RevisionEvent {
            record_id: id.clone(),
            revision: updated.revision,
            kind: RevisionKind::Captured,
            reason,
            source,
        });
        Ok(updated)
    }

    pub fn transition_lifecycle(
        &self,
        id: &MemoryId,
        to: Lifecycle,
        reason: String,
        source: String,
    ) -> Result<MemoryRecord, MemoryError> {
        validate_text(&reason, "reason")?;
        validate_text(&source, "source")?;
        let mut state = self.state.lock().map_err(|_| MemoryError::Unavailable)?;
        let updated = {
            let record = state
                .records
                .get_mut(id)
                .ok_or_else(|| MemoryError::NotFound(id.clone()))?;
            if !record.lifecycle.can_transition_to(to) {
                return Err(MemoryError::InvalidLifecycle {
                    from: record.lifecycle,
                    to,
                });
            }
            record.lifecycle = to;
            if matches!(
                to,
                Lifecycle::Suppressed
                    | Lifecycle::Quarantined
                    | Lifecycle::Archived
                    | Lifecycle::Forgotten
            ) {
                record.influence_allowed = false;
            }
            record.clone()
        };
        state.history.push(RevisionEvent {
            record_id: id.clone(),
            revision: updated.revision,
            kind: RevisionKind::LifecycleChanged,
            reason,
            source,
        });
        Ok(updated)
    }

    pub fn allow_influence(
        &self,
        id: &MemoryId,
        support: Vec<String>,
    ) -> Result<MemoryRecord, MemoryError> {
        let mut state = self.state.lock().map_err(|_| MemoryError::Unavailable)?;
        let record = state
            .records
            .get_mut(id)
            .ok_or_else(|| MemoryError::NotFound(id.clone()))?;
        if record.lifecycle != Lifecycle::Active
            || matches!(
                record.status,
                EpistemicStatus::Rejected | EpistemicStatus::Unknown | EpistemicStatus::Contested
            )
            || support.is_empty()
        {
            return Err(MemoryError::InfluenceDenied);
        }
        record.support.extend(support);
        unique_strings(&mut record.support);
        record.influence_allowed = true;
        Ok(record.clone())
    }

    /// Exact matches precede broader matches; negative records are returned first.
    /// A session receives a record at most once until its influence is invalidated.
    pub fn retrieve(&self, request: RetrievalRequest) -> Result<Vec<RetrievedMemory>, MemoryError> {
        validate_text(&request.scope, "scope")?;
        let limit = request.limit.min(MAX_RESULTS);
        let mut state = self.state.lock().map_err(|_| MemoryError::Unavailable)?;
        let delivered = request.session.as_ref().map(|s| state.delivered.get(s));
        let mut scored = Vec::new();
        for record in state.records.values() {
            if record.scope != request.scope
                || record.lifecycle != Lifecycle::Active
                || !record.influence_allowed
            {
                continue;
            }
            if delivered.is_some_and(|set| set.is_some_and(|items| items.contains(&record.id))) {
                continue;
            }
            let mut best = None;
            for wanted in &request.cues {
                for cue in &record.cues {
                    if wanted.kind != cue.kind {
                        continue;
                    }
                    let match_kind = if wanted.value == cue.value {
                        Some(if record.kind == RecordKind::Failure {
                            MatchKind::NegativeExact
                        } else {
                            MatchKind::Exact
                        })
                    } else if !cue.exact && cue.value.starts_with(&wanted.value) {
                        Some(MatchKind::Prefix)
                    } else if wanted.kind == CueKind::ErrorSignature
                        && wanted.value.starts_with("sig:")
                        && cue
                            .value
                            .starts_with(&wanted.value[..wanted.value.len().min(12)])
                    {
                        Some(MatchKind::Signature)
                    } else {
                        None
                    };
                    if match_kind.is_some() {
                        best = best.or(match_kind);
                    }
                }
            }
            if let Some(kind) = best {
                scored.push((
                    if matches!(kind, MatchKind::NegativeExact) {
                        0
                    } else {
                        kind as u8
                    },
                    record.revision,
                    kind,
                    record.clone(),
                ));
            }
        }
        scored.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.3.id.cmp(&b.3.id))
        });
        let result: Vec<_> = scored
            .into_iter()
            .take(limit)
            .enumerate()
            .map(|(rank, (_, _, kind, record))| RetrievedMemory {
                record,
                match_kind: kind,
                rank,
            })
            .collect();
        if let Some(session) = request.session {
            let set = state.delivered.entry(session).or_default();
            for item in &result {
                set.insert(item.record.id.clone());
            }
        }
        Ok(result)
    }

    pub fn understanding(&self, scope: &str) -> Result<UnderstandingView, MemoryError> {
        validate_text(scope, "scope")?;
        let state = self.state.lock().map_err(|_| MemoryError::Unavailable)?;
        let mut records = Vec::new();
        let mut negative = Vec::new();
        let mut unknowns = Vec::new();
        for record in state
            .records
            .values()
            .filter(|r| r.scope == scope && r.lifecycle == Lifecycle::Active)
        {
            if record.kind == RecordKind::Failure {
                negative.push(record.id.clone());
            } else if record.status == EpistemicStatus::Unknown {
                unknowns.push(record.id.clone());
            } else if record.influence_allowed {
                records.push(record.id.clone());
            }
        }
        let digest_input = (&scope, &records, &negative, &unknowns, state.next_revision);
        let state_digest = stable_digest(
            &serde_json::to_vec(&digest_input)
                .map_err(|e| MemoryError::Serialization(e.to_string()))?,
        );
        Ok(UnderstandingView {
            scope: scope.to_owned(),
            revision: state.next_revision,
            records,
            negative_records: negative,
            unknowns,
            state_digest,
        })
    }

    pub fn history(&self, id: Option<&MemoryId>) -> Result<Vec<RevisionEvent>, MemoryError> {
        let state = self.state.lock().map_err(|_| MemoryError::Unavailable)?;
        Ok(state
            .history
            .iter()
            .filter(|event| id.is_none_or(|wanted| &event.record_id == wanted))
            .cloned()
            .collect())
    }
}

fn classify(input: &ObservationInput) -> (RecordKind, EpistemicStatus) {
    match input.hint {
        ObservationHint::Failure => (RecordKind::Failure, EpistemicStatus::Observed),
        ObservationHint::Decision => (RecordKind::Decision, EpistemicStatus::Observed),
        ObservationHint::Outcome => (RecordKind::Outcome, EpistemicStatus::Observed),
        ObservationHint::Unknown => (RecordKind::Unknown, EpistemicStatus::Unknown),
        ObservationHint::ReuseCandidate => (RecordKind::Experience, EpistemicStatus::Observed),
        ObservationHint::Observation | ObservationHint::Auto => {
            (RecordKind::ObservationCandidate, EpistemicStatus::Observed)
        }
    }
}

fn stable_digest(bytes: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut output = String::new();
    for salt in 0_u64..4 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        salt.hash(&mut hasher);
        bytes.hash(&mut hasher);
        output.push_str(&format!("{:016x}", hasher.finish()));
    }
    output
}
