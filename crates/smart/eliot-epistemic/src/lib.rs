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
        for record in &self.records {
            for predecessor in &record.supersedes {
                if !handles.contains(predecessor) {
                    return Err(EpistemicError::MissingPredecessor {
                        handle: record.handle.clone(),
                        predecessor: predecessor.clone(),
                    });
                }
            }
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

const fn is_current_freshness(freshness: EvidenceFreshness) -> bool {
    matches!(
        freshness,
        EvidenceFreshness::ExactCandidate
            | EvidenceFreshness::ExactCommit
            | EvidenceFreshness::ExactQuiescedWorktree
    )
}

/// Resolve one question without ranking by prose, vote count, or model output.
#[allow(clippy::too_many_lines)]
pub fn resolve(request: &PositionRequest) -> Result<CurrentEpistemicPosition, EpistemicError> {
    request.validate()?;
    let mut direct = BTreeSet::new();
    let mut supporting = BTreeSet::new();
    let mut rivals = BTreeSet::new();
    let mut stale = BTreeSet::new();
    let mut unknowns = BTreeSet::new();
    let mut inquiries = BTreeSet::new();
    let mut current = Vec::new();
    let mut superseded = request
        .records
        .iter()
        .flat_map(|record| record.supersedes.iter().cloned())
        .collect::<BTreeSet<_>>();

    for record in &request.records {
        if let Some(note) = &record.note {
            inquiries.insert(note.clone());
        }
        if !is_current_freshness(record.evidence.freshness) {
            stale.insert(record.handle.clone());
            let inquiry = if record.evidence.freshness == EvidenceFreshness::Stale {
                format!("revalidate {}", record.handle)
            } else {
                format!("establish freshness for {}", record.handle)
            };
            inquiries.insert(inquiry);
            match record.evidence.status {
                EpistemicStatus::Unknown => {
                    unknowns.insert(record.subject.clone());
                    inquiries.insert(format!("obtain evidence for {}", record.subject));
                }
                EpistemicStatus::Superseded => {
                    superseded.insert(record.handle.clone());
                }
                _ => {}
            }
            continue;
        }
        if superseded.contains(&record.handle) {
            if record.evidence.status == EpistemicStatus::Unknown {
                unknowns.insert(record.subject.clone());
                inquiries.insert(format!("obtain evidence for {}", record.subject));
            }
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
    let provenance = provenance_for(&request.records);
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

fn provenance_for(records: &[EpistemicRecord]) -> ProvenanceView {
    // Every admitted record remains addressable, including unknown and stale
    // evidence that cannot promote the current position.
    let selected: BTreeSet<_> = records.iter().map(|record| record.handle.clone()).collect();
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
    let mixed_sources = sources.len() > 1;
    ProvenanceView {
        record_handles: selected.into_iter().collect(),
        source_ids: sources.into_iter().collect(),
        raw_handles: raw.into_iter().collect(),
        revisions: revisions.into_iter().collect(),
        mixed_sources,
        assertability,
    }
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ContractId, ResourceGeneration, SourceId};
    use eliot_evidence::{EvidenceAuthority, EvidenceCoverage, Provenance, VerificationBinding};

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn id(value: &str) -> ArtifactId {
        ArtifactId::new(value).expect("valid fixture artifact id")
    }

    fn envelope(
        status: EpistemicStatus,
        freshness: EvidenceFreshness,
        source: &str,
        revision: &str,
    ) -> EvidenceEnvelope {
        let assertability = match status {
            EpistemicStatus::Supported | EpistemicStatus::Verified => Assertability::Assertable,
            _ => Assertability::NonAssertableUnverified,
        };
        let verification = (status == EpistemicStatus::Verified).then(|| VerificationBinding {
            contract_id: ContractId::new(format!("contract:{source}"))
                .expect("valid fixture contract id"),
            run_id: id(&format!("run:{source}:{revision}")),
            revision: revision.to_owned(),
        });
        EvidenceEnvelope {
            authority: EvidenceAuthority::DeterministicRuntimeTest,
            freshness,
            coverage: EvidenceCoverage::CompleteForScope,
            status,
            assertability,
            provenance: Provenance {
                source_id: SourceId::new(source).expect("valid fixture source id"),
                capture_route: "fixture.epistemic".to_owned(),
                scope: "scope".to_owned(),
                raw_handle: Some(format!("raw:{source}:{revision}")),
                revision: Some(revision.to_owned()),
            },
            verification,
            state_fence: fence(),
        }
    }

    fn record(
        handle: &str,
        status: EpistemicStatus,
        freshness: EvidenceFreshness,
        supersedes: Vec<ArtifactId>,
    ) -> EpistemicRecord {
        EpistemicRecord {
            handle: id(handle),
            subject: format!("subject:{handle}"),
            scope: "scope".to_owned(),
            evidence: envelope(status, freshness, &format!("source:{handle}"), handle),
            supersedes,
            note: None,
        }
    }

    fn request(records: Vec<EpistemicRecord>) -> PositionRequest {
        PositionRequest {
            question: "question".to_owned(),
            scope: "scope".to_owned(),
            state_fence: fence(),
            records,
        }
    }

    #[test]
    fn only_exact_current_verified_evidence_supports_position() {
        let current = record(
            "current",
            EpistemicStatus::Verified,
            EvidenceFreshness::ExactCandidate,
            Vec::new(),
        );
        let older = record(
            "older",
            EpistemicStatus::Verified,
            EvidenceFreshness::KnownOlderSnapshot,
            Vec::new(),
        );
        let unknown = record(
            "unknown",
            EpistemicStatus::Verified,
            EvidenceFreshness::Unknown,
            Vec::new(),
        );
        let result = resolve(&request(vec![current, older, unknown])).expect("valid request");

        assert_eq!(result.state, PositionState::Supported);
        assert_eq!(result.supporting_records, vec![id("current")]);
        assert_eq!(result.direct_observations, Vec::<ArtifactId>::new());
        assert_eq!(result.rival_records, Vec::<ArtifactId>::new());
        assert_eq!(result.stale_records, vec![id("older"), id("unknown")]);
        assert_eq!(
            result.provenance.record_handles,
            vec![id("current"), id("older"), id("unknown")]
        );
        assert_eq!(
            result.provenance.revisions,
            vec!["current", "older", "unknown"]
        );
        assert_eq!(
            result.provenance.raw_handles,
            vec![
                "raw:source:current:current",
                "raw:source:older:older",
                "raw:source:unknown:unknown"
            ]
        );
    }

    #[test]
    fn missing_predecessor_is_rejected_against_admitted_request_set() {
        let successor = record(
            "successor",
            EpistemicStatus::Verified,
            EvidenceFreshness::ExactCommit,
            vec![id("missing")],
        );

        assert!(matches!(
            resolve(&request(vec![successor])),
            Err(EpistemicError::MissingPredecessor { handle, predecessor })
                if handle == id("successor") && predecessor == id("missing")
        ));
    }

    #[test]
    fn self_and_duplicate_predecessors_are_rejected() {
        let self_reference = record(
            "self",
            EpistemicStatus::Supported,
            EvidenceFreshness::ExactCandidate,
            vec![id("self")],
        );
        assert!(matches!(
            resolve(&request(vec![self_reference])),
            Err(EpistemicError::SelfSupersession { handle }) if handle == id("self")
        ));

        let duplicate = record(
            "successor",
            EpistemicStatus::Supported,
            EvidenceFreshness::ExactCandidate,
            vec![id("predecessor"), id("predecessor")],
        );
        let predecessor = record(
            "predecessor",
            EpistemicStatus::Supported,
            EvidenceFreshness::ExactCandidate,
            Vec::new(),
        );
        assert!(matches!(
            resolve(&request(vec![duplicate, predecessor])),
            Err(EpistemicError::DuplicatePredecessor { handle, predecessor })
                if handle == id("successor") && predecessor == id("predecessor")
        ));
    }

    #[test]
    fn stale_and_unknown_freshness_remain_addressable_without_current_promotion() {
        let older = record(
            "older",
            EpistemicStatus::Verified,
            EvidenceFreshness::KnownOlderSnapshot,
            Vec::new(),
        );
        let unknown = record(
            "unknown",
            EpistemicStatus::Unknown,
            EvidenceFreshness::Unknown,
            Vec::new(),
        );
        let result = resolve(&request(vec![older, unknown])).expect("valid request");

        assert_eq!(result.state, PositionState::Stale);
        assert!(result.direct_observations.is_empty());
        assert!(result.supporting_records.is_empty());
        assert!(result.rival_records.is_empty());
        assert_eq!(result.stale_records, vec![id("older"), id("unknown")]);
        assert!(result.unknowns.contains(&"subject:unknown".to_owned()));
        assert!(result.provenance.record_handles.contains(&id("older")));
        assert!(result.provenance.record_handles.contains(&id("unknown")));
    }

    #[test]
    fn superseded_lineage_and_provenance_are_permutation_invariant() {
        let predecessor_a = record(
            "predecessor-a",
            EpistemicStatus::Verified,
            EvidenceFreshness::ExactCommit,
            Vec::new(),
        );
        let predecessor_z = record(
            "predecessor-z",
            EpistemicStatus::Verified,
            EvidenceFreshness::ExactCommit,
            Vec::new(),
        );
        let successor = record(
            "successor",
            EpistemicStatus::Verified,
            EvidenceFreshness::ExactCandidate,
            vec![id("predecessor-z"), id("predecessor-a")],
        );
        let original_verification = successor.evidence.verification.clone();

        let first = resolve(&request(vec![
            successor.clone(),
            predecessor_z.clone(),
            predecessor_a.clone(),
        ]))
        .expect("valid request");

        let mut reordered_successor = successor.clone();
        reordered_successor.supersedes.reverse();
        let second = resolve(&request(vec![
            predecessor_a,
            reordered_successor,
            predecessor_z,
        ]))
        .expect("valid request");

        assert_eq!(first, second);
        assert_eq!(first.supporting_records, vec![id("successor")]);
        assert_eq!(
            first.superseded_records,
            vec![id("predecessor-a"), id("predecessor-z")]
        );
        assert_eq!(
            first.provenance.record_handles,
            vec![id("predecessor-a"), id("predecessor-z"), id("successor")]
        );
        assert_eq!(successor.evidence.verification, original_verification);
    }
}
