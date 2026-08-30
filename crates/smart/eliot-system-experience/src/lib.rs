//! Stateless, bounded projection over Governor-owned system-experience evidence.
//!
//! This crate is a compatibility extraction from the retired in-memory
//! `SystemExperienceOwner`. It owns no canonical state, lifecycle, graph,
//! revision, support, accessibility, influence, or persistence. Callers supply
//! one immutable, denominator-bound read set; this crate validates and projects
//! it deterministically.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, TaskId};
use eliot_evidence::{
    EpistemicStatus, EvidenceError, ExperienceRecord, LifecycleState, RelationRecord,
    evidence_shape_digest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this compatibility projection surface.
pub const CONTRACT_NAME: &str = "eliot.smart.system_experience_projection";
/// Breaking revision that removes the duplicate mutable state owner.
pub const CONTRACT_VERSION: &str = "2.0.0";
/// Maximum source records accepted by one bounded projection call.
pub const MAX_SOURCE_RECORDS: usize = 4_096;
/// Maximum relations accepted by one bounded projection call.
pub const MAX_SOURCE_RELATIONS: usize = 8_192;
/// Maximum records returned by one projection.
pub const MAX_QUERY_RESULTS: usize = 128;
/// Maximum conjunctive terms accepted by one query.
pub const MAX_QUERY_TERMS: usize = 16;
/// Maximum UTF-8 bytes in one normalized term.
pub const MAX_QUERY_TERM_BYTES: usize = 256;

/// Exact denominator state for the immutable provider-owned read set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ExperienceSourceCoverage {
    /// Every record in the frozen denominator is present.
    Complete {
        /// Exact independently recheckable denominator.
        expected_records: usize,
    },
    /// The supplied read set is known to omit records from the denominator.
    Partial {
        /// Exact independently recheckable denominator.
        expected_records: usize,
        /// Exact records absent from this input projection.
        omitted_records: usize,
    },
}

impl ExperienceSourceCoverage {
    fn validate(&self, actual_records: usize) -> Result<(), ExperienceProjectionError> {
        let (expected_records, declared_omitted) = match self {
            Self::Complete { expected_records } => (*expected_records, 0),
            Self::Partial {
                expected_records,
                omitted_records,
            } => (*expected_records, *omitted_records),
        };
        if expected_records > MAX_SOURCE_RECORDS {
            return Err(ExperienceProjectionError::LimitExceeded {
                field: "coverage.expected_records",
                limit: MAX_SOURCE_RECORDS,
            });
        }
        let actual_omitted = expected_records.checked_sub(actual_records).ok_or(
            ExperienceProjectionError::CoverageMismatch {
                expected: expected_records,
                actual: actual_records,
                declared_omitted,
            },
        )?;
        if actual_omitted != declared_omitted
            || matches!(self, Self::Partial { .. }) && declared_omitted == 0
        {
            return Err(ExperienceProjectionError::CoverageMismatch {
                expected: expected_records,
                actual: actual_records,
                declared_omitted,
            });
        }
        Ok(())
    }
}

/// Caller-supplied bounded query over one immutable owner projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperienceProjectionRequest {
    /// Non-zero revision assigned by the real provider/owner.
    pub source_revision: u64,
    /// Exact WorkScope-relative scope admitted by the provider.
    pub scope: String,
    /// Frozen source denominator and any known omission.
    pub coverage: ExperienceSourceCoverage,
    /// Optional task filter; it never creates or selects a task.
    pub task_id: Option<TaskId>,
    /// Optional lifecycle filter; it never changes lifecycle.
    pub lifecycle: Option<LifecycleState>,
    /// Allowed epistemic states. Empty means no status filter.
    pub statuses: Vec<EpistemicStatus>,
    /// Case-insensitive conjunctive terms. Empty means no text filter.
    pub terms: Vec<String>,
    /// Requested result cap. Zero selects [`MAX_QUERY_RESULTS`].
    pub limit: usize,
}

/// Canonicalized query retained in the projection identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedExperienceQuery {
    pub task_id: Option<TaskId>,
    pub lifecycle: Option<LifecycleState>,
    pub statuses: Vec<EpistemicStatus>,
    pub terms: Vec<String>,
    pub limit: usize,
}

/// One deterministic result position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperienceMatch {
    pub record: ExperienceRecord,
    /// Zero-based position after deterministic identity ordering.
    pub rank: usize,
}

/// Immutable read-only projection produced from one exact source revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperienceProjection {
    pub contract_name: String,
    pub contract_version: String,
    pub source_revision: u64,
    pub scope: String,
    pub coverage: ExperienceSourceCoverage,
    pub query: NormalizedExperienceQuery,
    pub source_record_count: usize,
    pub matched_record_count: usize,
    pub returned_record_count: usize,
    pub omitted_by_limit: usize,
    pub matches: Vec<ExperienceMatch>,
    /// Relations whose two endpoints are present in `matches`.
    pub relations: Vec<RelationRecord>,
    pub digest: String,
}

impl ExperienceProjection {
    /// Revalidates output shape and content identity without consulting a store.
    pub fn validate(&self) -> Result<(), ExperienceProjectionError> {
        if self.contract_name != CONTRACT_NAME || self.contract_version != CONTRACT_VERSION {
            return Err(ExperienceProjectionError::Invalid {
                field: "projection.contract",
                reason: "unsupported contract identity or version",
            });
        }
        validate_text(&self.scope, "projection.scope")?;
        if self.source_revision == 0 {
            return Err(ExperienceProjectionError::Invalid {
                field: "projection.source_revision",
                reason: "must be non-zero",
            });
        }
        self.coverage.validate(self.source_record_count)?;
        if self.returned_record_count != self.matches.len()
            || self.matched_record_count < self.returned_record_count
            || self.omitted_by_limit
                != self
                    .matched_record_count
                    .saturating_sub(self.returned_record_count)
        {
            return Err(ExperienceProjectionError::Invalid {
                field: "projection.counts",
                reason: "matched, returned, and omitted counts are inconsistent",
            });
        }
        let mut ids = BTreeSet::new();
        for (rank, item) in self.matches.iter().enumerate() {
            item.record.validate()?;
            if item.record.evidence.provenance.scope != self.scope {
                return Err(ExperienceProjectionError::WrongScope {
                    experience_id: item.record.experience_id.clone(),
                    expected: self.scope.clone(),
                    actual: item.record.evidence.provenance.scope.clone(),
                });
            }
            if item.rank != rank || !ids.insert(item.record.experience_id.clone()) {
                return Err(ExperienceProjectionError::Invalid {
                    field: "projection.matches",
                    reason: "ranks must be contiguous and identities unique",
                });
            }
        }
        let mut relation_ids = BTreeSet::new();
        for relation in &self.relations {
            relation.validate()?;
            if !relation_ids.insert(relation.relation_id.clone()) {
                return Err(ExperienceProjectionError::DuplicateRelation(
                    relation.relation_id.clone(),
                ));
            }
            if !ids.contains(&relation.from) {
                return Err(ExperienceProjectionError::UnknownEndpoint(
                    relation.from.clone(),
                ));
            }
            if !ids.contains(&relation.to) {
                return Err(ExperienceProjectionError::UnknownEndpoint(
                    relation.to.clone(),
                ));
            }
        }
        let expected = projection_digest(self)?;
        if self.digest != expected {
            return Err(ExperienceProjectionError::DigestMismatch);
        }
        Ok(())
    }
}

/// Pure projection failures. No variant implies that provider or canonical
/// state was changed.
#[derive(Debug, Error)]
pub enum ExperienceProjectionError {
    #[error("evidence contract rejected the input: {0}")]
    Evidence(#[from] EvidenceError),
    #[error("{field} is invalid: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("{field} exceeds the bounded limit {limit}")]
    LimitExceeded { field: &'static str, limit: usize },
    #[error(
        "coverage mismatch: expected {expected}, supplied {actual}, declared omitted {declared_omitted}"
    )]
    CoverageMismatch {
        expected: usize,
        actual: usize,
        declared_omitted: usize,
    },
    #[error("duplicate experience identity: {0}")]
    DuplicateExperience(ArtifactId),
    #[error("duplicate relation identity: {0}")]
    DuplicateRelation(ArtifactId),
    #[error("relation endpoint is absent from the immutable source set: {0}")]
    UnknownEndpoint(ArtifactId),
    #[error("experience {experience_id} belongs to {actual}, expected {expected}")]
    WrongScope {
        experience_id: ArtifactId,
        expected: String,
        actual: String,
    },
    #[error("projection digest does not match its canonical content")]
    DigestMismatch,
}

/// Validates and deterministically projects immutable experience evidence.
///
/// This function performs no I/O, persistence, lifecycle transition, relation
/// admission, support update, usage tracking, reinforcement, or authority
/// decision. Input order cannot change the output identity.
pub fn project_experience(
    request: ExperienceProjectionRequest,
    experiences: &[ExperienceRecord],
    relations: &[RelationRecord],
) -> Result<ExperienceProjection, ExperienceProjectionError> {
    if request.source_revision == 0 {
        return Err(ExperienceProjectionError::Invalid {
            field: "request.source_revision",
            reason: "must be non-zero",
        });
    }
    validate_text(&request.scope, "request.scope")?;
    if experiences.len() > MAX_SOURCE_RECORDS {
        return Err(ExperienceProjectionError::LimitExceeded {
            field: "experiences",
            limit: MAX_SOURCE_RECORDS,
        });
    }
    if relations.len() > MAX_SOURCE_RELATIONS {
        return Err(ExperienceProjectionError::LimitExceeded {
            field: "relations",
            limit: MAX_SOURCE_RELATIONS,
        });
    }
    request.coverage.validate(experiences.len())?;
    let query = normalize_query(&request)?;

    let mut source_ids = BTreeSet::new();
    let mut ordered = Vec::with_capacity(experiences.len());
    for record in experiences {
        record.validate()?;
        if record.evidence.provenance.scope != request.scope {
            return Err(ExperienceProjectionError::WrongScope {
                experience_id: record.experience_id.clone(),
                expected: request.scope.clone(),
                actual: record.evidence.provenance.scope.clone(),
            });
        }
        if !source_ids.insert(record.experience_id.clone()) {
            return Err(ExperienceProjectionError::DuplicateExperience(
                record.experience_id.clone(),
            ));
        }
        ordered.push(record.clone());
    }
    ordered.sort_by(|left, right| left.experience_id.cmp(&right.experience_id));

    let mut relation_ids = BTreeSet::new();
    for relation in relations {
        relation.validate()?;
        if !relation_ids.insert(relation.relation_id.clone()) {
            return Err(ExperienceProjectionError::DuplicateRelation(
                relation.relation_id.clone(),
            ));
        }
        if !source_ids.contains(&relation.from) {
            return Err(ExperienceProjectionError::UnknownEndpoint(
                relation.from.clone(),
            ));
        }
        if !source_ids.contains(&relation.to) {
            return Err(ExperienceProjectionError::UnknownEndpoint(
                relation.to.clone(),
            ));
        }
    }

    let filtered = ordered
        .into_iter()
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
        .filter(|record| {
            query
                .terms
                .iter()
                .all(|term| contains_normalized_term(record, term))
        })
        .collect::<Vec<_>>();
    let matched_record_count = filtered.len();
    let returned = filtered
        .into_iter()
        .take(query.limit)
        .collect::<Vec<_>>();
    let returned_ids = returned
        .iter()
        .map(|record| record.experience_id.clone())
        .collect::<BTreeSet<_>>();
    let matches = returned
        .into_iter()
        .enumerate()
        .map(|(rank, record)| ExperienceMatch { record, rank })
        .collect::<Vec<_>>();
    let mut selected_relations = relations
        .iter()
        .filter(|relation| {
            returned_ids.contains(&relation.from) && returned_ids.contains(&relation.to)
        })
        .cloned()
        .collect::<Vec<_>>();
    selected_relations.sort_by(|left, right| left.relation_id.cmp(&right.relation_id));

    let returned_record_count = matches.len();
    let mut projection = ExperienceProjection {
        contract_name: CONTRACT_NAME.to_owned(),
        contract_version: CONTRACT_VERSION.to_owned(),
        source_revision: request.source_revision,
        scope: request.scope,
        coverage: request.coverage,
        query,
        source_record_count: experiences.len(),
        matched_record_count,
        returned_record_count,
        omitted_by_limit: matched_record_count.saturating_sub(returned_record_count),
        matches,
        relations: selected_relations,
        digest: String::new(),
    };
    projection.digest = projection_digest(&projection)?;
    projection.validate()?;
    Ok(projection)
}

fn normalize_query(
    request: &ExperienceProjectionRequest,
) -> Result<NormalizedExperienceQuery, ExperienceProjectionError> {
    if request.terms.len() > MAX_QUERY_TERMS {
        return Err(ExperienceProjectionError::LimitExceeded {
            field: "request.terms",
            limit: MAX_QUERY_TERMS,
        });
    }
    if request.limit > MAX_QUERY_RESULTS {
        return Err(ExperienceProjectionError::LimitExceeded {
            field: "request.limit",
            limit: MAX_QUERY_RESULTS,
        });
    }
    let mut terms = Vec::with_capacity(request.terms.len());
    for term in &request.terms {
        let normalized = term.trim().to_lowercase();
        if normalized.is_empty() || normalized.chars().any(char::is_control) {
            return Err(ExperienceProjectionError::Invalid {
                field: "request.terms",
                reason: "terms must be non-blank and free of control characters",
            });
        }
        if normalized.len() > MAX_QUERY_TERM_BYTES {
            return Err(ExperienceProjectionError::LimitExceeded {
                field: "request.term",
                limit: MAX_QUERY_TERM_BYTES,
            });
        }
        terms.push(normalized);
    }
    terms.sort();
    terms.dedup();

    let mut statuses = request.statuses.clone();
    statuses.sort_by_key(|status| status_order(*status));
    statuses.dedup();

    Ok(NormalizedExperienceQuery {
        task_id: request.task_id.clone(),
        lifecycle: request.lifecycle,
        statuses,
        terms,
        limit: if request.limit == 0 {
            MAX_QUERY_RESULTS
        } else {
            request.limit
        },
    })
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ExperienceProjectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ExperienceProjectionError::Invalid {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

const fn status_order(status: EpistemicStatus) -> u8 {
    match status {
        EpistemicStatus::Observed => 0,
        EpistemicStatus::Supported => 1,
        EpistemicStatus::Verified => 2,
        EpistemicStatus::Contested => 3,
        EpistemicStatus::Stale => 4,
        EpistemicStatus::Superseded => 5,
        EpistemicStatus::Rejected => 6,
        EpistemicStatus::Unknown => 7,
    }
}

fn contains_normalized_term(record: &ExperienceRecord, normalized_term: &str) -> bool {
    [
        record.episode.as_str(),
        record.action.as_str(),
        record.outcome.as_str(),
    ]
    .iter()
    .any(|text| text.to_lowercase().contains(normalized_term))
}

fn projection_digest(
    projection: &ExperienceProjection,
) -> Result<String, ExperienceProjectionError> {
    evidence_shape_digest(&(
        projection.contract_name.as_str(),
        projection.contract_version.as_str(),
        projection.source_revision,
        projection.scope.as_str(),
        &projection.coverage,
        &projection.query,
        projection.source_record_count,
        projection.matched_record_count,
        projection.returned_record_count,
        projection.omitted_by_limit,
        &projection.matches,
        &projection.relations,
    ))
    .map_err(ExperienceProjectionError::Evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ArtifactId, AuthorityEpoch, ResourceGeneration, SourceId, StateFence, TaskId,
    };
    use eliot_evidence::{
        Assertability, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope, EvidenceFreshness,
        Provenance, RelationKind,
    };

    fn provenance(scope: &str) -> Result<Provenance, Box<dyn std::error::Error>> {
        Ok(Provenance {
            source_id: SourceId::new("fixture-source")?,
            capture_route: "fixture.route".to_owned(),
            scope: scope.to_owned(),
            raw_handle: Some("eliot://evidence/fixture".to_owned()),
            revision: Some("r1".to_owned()),
        })
    }

    fn experience(
        id: &str,
        scope: &str,
        task: &str,
        outcome: &str,
    ) -> Result<ExperienceRecord, Box<dyn std::error::Error>> {
        Ok(ExperienceRecord {
            experience_id: ArtifactId::new(id)?,
            task_id: Some(TaskId::new(task)?),
            episode: format!("episode {id}"),
            action: "run exact verifier".to_owned(),
            outcome: outcome.to_owned(),
            evidence: EvidenceEnvelope {
                authority: EvidenceAuthority::DeterministicRuntimeTest,
                freshness: EvidenceFreshness::ExactCandidate,
                coverage: EvidenceCoverage::CompleteForScope,
                status: EpistemicStatus::Observed,
                assertability: Assertability::NonAssertableUnverified,
                provenance: provenance(scope)?,
                verification: None,
                state_fence: StateFence::new(
                    AuthorityEpoch::genesis(),
                    ResourceGeneration::genesis(),
                ),
            },
            lifecycle: LifecycleState::Active,
        })
    }

    fn relation(
        id: &str,
        from: &str,
        to: &str,
    ) -> Result<RelationRecord, Box<dyn std::error::Error>> {
        Ok(RelationRecord {
            relation_id: ArtifactId::new(id)?,
            from: ArtifactId::new(from)?,
            to: ArtifactId::new(to)?,
            kind: RelationKind::ObservedIn,
            status: EpistemicStatus::Observed,
            provenance: provenance("scope-a")?,
            lifecycle: LifecycleState::Active,
        })
    }

    fn request(expected_records: usize) -> ExperienceProjectionRequest {
        ExperienceProjectionRequest {
            source_revision: 7,
            scope: "scope-a".to_owned(),
            coverage: ExperienceSourceCoverage::Complete { expected_records },
            task_id: None,
            lifecycle: Some(LifecycleState::Active),
            statuses: vec![EpistemicStatus::Observed],
            terms: vec!["pass".to_owned()],
            limit: MAX_QUERY_RESULTS,
        }
    }

    #[test]
    fn projection_is_permutation_invariant() -> Result<(), Box<dyn std::error::Error>> {
        let first = experience("exp-a", "scope-a", "task-a", "passed")?;
        let second = experience("exp-b", "scope-a", "task-a", "passed")?;
        let edge = relation("rel-a", "exp-a", "exp-b")?;

        let left = project_experience(
            request(2),
            &[second.clone(), first.clone()],
            std::slice::from_ref(&edge),
        )?;
        let right = project_experience(request(2), &[first, second], &[edge])?;

        assert_eq!(left, right);
        assert_eq!(left.matches[0].record.experience_id, ArtifactId::new("exp-a")?);
        Ok(())
    }

    #[test]
    fn complete_coverage_requires_exact_denominator()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = experience("exp-a", "scope-a", "task-a", "passed")?;
        assert!(matches!(
            project_experience(request(2), &[record], &[]),
            Err(ExperienceProjectionError::CoverageMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn partial_coverage_and_query_omission_remain_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut projection_request = request(3);
        projection_request.coverage = ExperienceSourceCoverage::Partial {
            expected_records: 3,
            omitted_records: 1,
        };
        projection_request.limit = 1;
        let records = [
            experience("exp-a", "scope-a", "task-a", "passed")?,
            experience("exp-b", "scope-a", "task-a", "passed")?,
        ];
        let projection = project_experience(projection_request, &records, &[])?;
        assert!(matches!(
            projection.coverage,
            ExperienceSourceCoverage::Partial {
                expected_records: 3,
                omitted_records: 1
            }
        ));
        assert_eq!(projection.matched_record_count, 2);
        assert_eq!(projection.returned_record_count, 1);
        assert_eq!(projection.omitted_by_limit, 1);
        Ok(())
    }

    #[test]
    fn wrong_scope_and_unknown_relation_endpoint_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let wrong_scope = experience("exp-a", "scope-b", "task-a", "passed")?;
        assert!(matches!(
            project_experience(request(1), &[wrong_scope], &[]),
            Err(ExperienceProjectionError::WrongScope { .. })
        ));

        let record = experience("exp-a", "scope-a", "task-a", "passed")?;
        let edge = relation("rel-a", "exp-a", "missing")?;
        assert!(matches!(
            project_experience(request(1), &[record], &[edge]),
            Err(ExperienceProjectionError::UnknownEndpoint(_))
        ));
        Ok(())
    }

    #[test]
    fn duplicate_identity_and_tampered_digest_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let record = experience("exp-a", "scope-a", "task-a", "passed")?;
        assert!(matches!(
            project_experience(request(2), &[record.clone(), record.clone()], &[]),
            Err(ExperienceProjectionError::DuplicateExperience(_))
        ));

        let mut projection = project_experience(request(1), &[record], &[])?;
        projection.digest = "0".repeat(64);
        assert!(matches!(
            projection.validate(),
            Err(ExperienceProjectionError::DigestMismatch)
        ));
        Ok(())
    }
}
