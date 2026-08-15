//! Bounded, read-only curation of canonical memory.
//!
//! Curation is a policy projection, not a second memory store.  The owner
//! accepts an already materialized, revision-fenced canonical snapshot and
//! emits deterministic, reversible proposals.  It never changes a record,
//! promotes epistemic status, or treats writer-supplied utility as authority.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.smart.memory_curation";
pub const CONTRACT_VERSION: &str = "1.0.0";
pub const RULESET_VERSION: &str = "eliot-l13-curation-v1";
pub const MAX_SCAN_RECORDS: usize = 1_000;
pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_REFERENCE_COUNT: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CurationError {
    #[error("{field} is blank or contains a control character")]
    InvalidText { field: &'static str },
    #[error("{field} exceeds {maximum} items")]
    TooMany { field: &'static str, maximum: usize },
    #[error("requested page size must be between 1 and {MAX_PAGE_SIZE}")]
    InvalidPageSize,
    #[error("unsupported curation ruleset: {0}")]
    UnsupportedRuleset(String),
    #[error("snapshot revision is required")]
    MissingRevision,
    #[error("snapshot revision {requested} is newer than record revision {actual}")]
    FutureRecord { requested: u64, actual: u64 },
    #[error("record belongs to a different curation scope")]
    ScopeMismatch,
    #[error("snapshot contains duplicate canonical handle {0}")]
    DuplicateHandle(String),
    #[error("cursor does not belong to this curation plan")]
    InvalidCursor,
    #[error("cursor is outside the stable result set")]
    CursorOutOfRange,
    #[error("curation owner is unavailable")]
    Unavailable,
}

fn text(value: &str, field: &'static str) -> Result<(), CurationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(CurationError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn bounded<T>(items: &[T], field: &'static str, maximum: usize) -> Result<(), CurationError> {
    if items.len() > maximum {
        Err(CurationError::TooMany { field, maximum })
    } else {
        Ok(())
    }
}

/// A canonical record projection supplied by the storage owner.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationRecord {
    pub handle: String,
    pub record_kind: String,
    pub scope: String,
    pub revision: u64,
    pub lifecycle: LifecycleState,
    pub status: String,
    pub content_digest: String,
    pub metadata: CurationMetadata,
}

impl CurationRecord {
    pub fn validate(&self, requested_revision: u64) -> Result<(), CurationError> {
        text(&self.handle, "record.handle")?;
        text(&self.record_kind, "record.record_kind")?;
        text(&self.scope, "record.scope")?;
        text(&self.content_digest, "record.content_digest")?;
        if self.revision > requested_revision {
            return Err(CurationError::FutureRecord {
                requested: requested_revision,
                actual: self.revision,
            });
        }
        self.metadata.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Active,
    Restored,
    Dormant,
    Suppressed,
    Quarantined,
    Archived,
    Forgotten,
    Superseded,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationMetadata {
    pub duplicate_of: Option<String>,
    pub semantic_duplicate_of: Option<String>,
    pub semantic_equivalence_verified: bool,
    pub scope_match: Option<bool>,
    pub superseded_by: Option<String>,
    pub stale_reason_ref: Option<String>,
    pub unsafe_instruction: bool,
    pub evidence_sufficient: bool,
    pub unsafe_evidence_refs: Vec<String>,
    pub protected: bool,
    pub current_truth: bool,
    pub audit_required: bool,
    pub role: Option<ProtectionRole>,
    pub evidence_refs: Vec<String>,
    pub counterevidence_refs: Vec<String>,
    pub utility_score: Option<f64>,
    pub utility_delta: Option<f64>,
    pub repeat_count: Option<u32>,
}

impl CurationMetadata {
    fn validate(&self) -> Result<(), CurationError> {
        for (field, values) in [
            ("metadata.unsafe_evidence_refs", &self.unsafe_evidence_refs),
            ("metadata.evidence_refs", &self.evidence_refs),
            ("metadata.counterevidence_refs", &self.counterevidence_refs),
        ] {
            bounded(values, field, MAX_REFERENCE_COUNT)?;
            for value in values {
                text(value, field)?;
            }
        }
        for (field, value) in [
            ("metadata.duplicate_of", self.duplicate_of.as_ref()),
            ("metadata.semantic_duplicate_of", self.semantic_duplicate_of.as_ref()),
            ("metadata.superseded_by", self.superseded_by.as_ref()),
            ("metadata.stale_reason_ref", self.stale_reason_ref.as_ref()),
        ] {
            if let Some(value) = value {
                text(value, field)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionRole {
    Counterexample,
    Minority,
    Protected,
    CurrentTruth,
    AuditHistory,
    FailureFingerprint,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Duplicate,
    SemanticDuplicate,
    WrongScope,
    LowUtilityInsufficientEvidence,
    UnsafeInstruction,
    StaleSuperseded,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReversibleAction {
    ProposeArchive,
    Archive,
    Suppress,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationCandidate {
    pub candidate_id: String,
    pub handle: String,
    pub record_kind: String,
    pub lifecycle: LifecycleState,
    pub finding: FindingKind,
    pub evidence_refs: Vec<String>,
    pub counterevidence_refs: Vec<String>,
    pub confidence: u8,
    pub proposed_action: ReversibleAction,
    pub restore_requirements: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorpusProfile {
    pub scanned_records: usize,
    pub scan_limit: usize,
    pub scan_truncated: bool,
    pub record_kind_counts: BTreeMap<String, usize>,
    pub lifecycle_counts: BTreeMap<LifecycleState, usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationPreview {
    pub scope: String,
    pub snapshot_revision: u64,
    pub ruleset_version: String,
    pub read_only: bool,
    pub corpus_profile: CorpusProfile,
    pub candidates: Vec<CurationCandidate>,
    pub protected_refs: Vec<String>,
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub total_matching: usize,
    pub total_is_exact: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreviewRequest {
    pub scope: String,
    pub snapshot_revision: Option<u64>,
    pub ruleset_version: String,
    pub page_size: usize,
    pub cursor: Option<String>,
}

impl PreviewRequest {
    fn validate(&self) -> Result<u64, CurationError> {
        text(&self.scope, "scope")?;
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(CurationError::InvalidPageSize);
        }
        if self.ruleset_version != RULESET_VERSION {
            return Err(CurationError::UnsupportedRuleset(self.ruleset_version.clone()));
        }
        self.snapshot_revision.ok_or(CurationError::MissingRevision)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryCurationOwner;

impl Default for MemoryCurationOwner {
    fn default() -> Self { Self }
}

impl MemoryCurationOwner {
    pub const fn new() -> Self { Self }

    /// Produces one stable page from a complete or bounded canonical snapshot.
    pub fn preview(
        &self,
        request: &PreviewRequest,
        records: &[CurationRecord],
        scan_is_exact: bool,
    ) -> Result<CurationPreview, CurationError> {
        let revision = request.validate()?;
        let scanned_records = &records[..records.len().min(MAX_SCAN_RECORDS)];
        let mut seen = BTreeSet::new();
        for record in scanned_records {
            record.validate(revision)?;
            if record.scope != request.scope {
                return Err(CurationError::ScopeMismatch);
            }
            if !seen.insert(record.handle.clone()) {
                return Err(CurationError::DuplicateHandle(record.handle.clone()));
            }
        }
        let mut candidates = Vec::new();
        let mut protected_refs = Vec::new();
        let mut kind_counts = BTreeMap::new();
        let mut lifecycle_counts = BTreeMap::new();
        for record in scanned_records {
            *kind_counts.entry(record.record_kind.clone()).or_insert(0) += 1;
            *lifecycle_counts.entry(record.lifecycle.clone()).or_insert(0) += 1;
            if is_protected(record) {
                protected_refs.push(record.handle.clone());
                continue;
            }
            if matches!(record.lifecycle, LifecycleState::Active | LifecycleState::Restored)
                && let Some(candidate) = candidate_for(record)
            {
                candidates.push(candidate);
            }
        }
        candidates.sort_by(|left, right| left.handle.cmp(&right.handle).then_with(|| left.finding.cmp(&right.finding)));
        protected_refs.sort();
        protected_refs.dedup();
        let total_matching = candidates.len();
        let offset = request
            .cursor
            .as_deref()
            .map(|cursor| parse_cursor(cursor, &request.scope, revision))
            .transpose()?
            .unwrap_or(0);
        if offset > total_matching {
            return Err(CurationError::CursorOutOfRange);
        }
        let end = offset.saturating_add(request.page_size).min(total_matching);
        let next_cursor = (end < total_matching).then(|| make_cursor(end, &request.scope, revision));
        Ok(CurationPreview {
            scope: request.scope.clone(),
            snapshot_revision: revision,
            ruleset_version: request.ruleset_version.clone(),
            read_only: true,
            corpus_profile: CorpusProfile {
                scanned_records: scanned_records.len(),
                scan_limit: MAX_SCAN_RECORDS,
                scan_truncated: !scan_is_exact || records.len() > MAX_SCAN_RECORDS,
                record_kind_counts: kind_counts,
                lifecycle_counts,
            },
            candidates: candidates[offset..end].to_vec(),
            protected_refs,
            cursor: request.cursor.clone(),
            next_cursor,
            total_matching,
            total_is_exact: scan_is_exact && records.len() <= MAX_SCAN_RECORDS,
        })
    }
}

fn is_protected(record: &CurationRecord) -> bool {
    record.metadata.protected
        || record.metadata.current_truth
        || record.metadata.audit_required
        || matches!(record.metadata.role, Some(ProtectionRole::Counterexample | ProtectionRole::Minority | ProtectionRole::Protected | ProtectionRole::CurrentTruth | ProtectionRole::AuditHistory))
        || (matches!(record.metadata.role, Some(ProtectionRole::FailureFingerprint)) && !record.metadata.evidence_sufficient)
        || record.status.eq_ignore_ascii_case("verified")
        || record.record_kind.eq_ignore_ascii_case("minority_pressure_record")
}

fn candidate_for(record: &CurationRecord) -> Option<CurationCandidate> {
    let (finding, action, confidence, signal_refs, requirements) = if let Some(target) = &record.metadata.duplicate_of {
        (FindingKind::Duplicate, ReversibleAction::Archive, 99, vec![target.clone()], vec!["restore receipt with operator reason".to_owned()])
    } else if let Some(target) = &record.metadata.semantic_duplicate_of {
        (FindingKind::SemanticDuplicate, if record.metadata.semantic_equivalence_verified { ReversibleAction::Archive } else { ReversibleAction::ProposeArchive }, if record.metadata.semantic_equivalence_verified { 92 } else { 70 }, vec![target.clone()], vec!["semantic equivalence must remain verified".to_owned(), "restore receipt with counterexample evidence".to_owned()])
    } else if record.metadata.scope_match == Some(false) {
        (FindingKind::WrongScope, ReversibleAction::Suppress, 95, Vec::new(), vec!["fresh scope applicability evidence".to_owned(), "restore receipt with revised scope".to_owned()])
    } else if record.metadata.unsafe_instruction && record.metadata.evidence_sufficient {
        (FindingKind::UnsafeInstruction, ReversibleAction::Suppress, 99, record.metadata.unsafe_evidence_refs.clone(), vec!["explicit safety revalidation".to_owned(), "restore receipt with operator evidence".to_owned()])
    } else if record.metadata.utility_score.is_some_and(|score| score <= 25.0) {
        (FindingKind::LowUtilityInsufficientEvidence, ReversibleAction::ProposeArchive, 40, vec!["writer_utility_score_is_not_canonical_evidence".to_owned()], vec!["derive utility from canonical inclusion, influence, verification, cost, and regret records".to_owned(), "preserve the active handle until the governed utility ledger is complete".to_owned()])
    } else if record.metadata.utility_delta.is_some_and(|delta| delta <= 0.0)
        && record.metadata.repeat_count.is_some_and(|count| count >= 2)
    {
        (FindingKind::LowUtilityInsufficientEvidence, ReversibleAction::ProposeArchive, 40, vec!["writer_utility_delta_is_not_canonical_evidence".to_owned()], vec!["derive repeated low delta from complete canonical use and outcome records".to_owned(), "preserve the active handle until the governed utility ledger is complete".to_owned()])
    } else if let Some(target) = &record.metadata.superseded_by {
        (FindingKind::StaleSuperseded, if record.metadata.stale_reason_ref.is_some() { ReversibleAction::Archive } else { ReversibleAction::ProposeArchive }, if record.metadata.stale_reason_ref.is_some() { 95 } else { 80 }, vec![target.clone()], vec!["superseding record must remain current".to_owned(), "restore receipt after freshness revalidation".to_owned()])
    } else {
        return None;
    };
    let mut evidence_refs = record.metadata.evidence_refs.clone();
    evidence_refs.extend(signal_refs);
    evidence_refs.sort();
    evidence_refs.dedup();
    let mut counterevidence_refs = record.metadata.counterevidence_refs.clone();
    counterevidence_refs.sort();
    counterevidence_refs.dedup();
    Some(CurationCandidate {
        candidate_id: candidate_id(&record.handle, finding),
        handle: record.handle.clone(),
        record_kind: record.record_kind.clone(),
        lifecycle: record.lifecycle.clone(),
        finding,
        evidence_refs,
        counterevidence_refs,
        confidence,
        proposed_action: action,
        restore_requirements: requirements,
    })
}

fn candidate_id(handle: &str, finding: FindingKind) -> String {
    let mut hasher = Hasher::new();
    hasher.update(handle.as_bytes());
    hasher.update(format!("::{finding:?}").as_bytes());
    format!("curation:{}", &hasher.finalize().to_hex().to_string()[..32])
}

fn make_cursor(offset: usize, scope: &str, revision: u64) -> String {
    format!("{offset}:{}", &digest(&format!("{scope}:{revision}"))[..24])
}

fn parse_cursor(value: &str, scope: &str, revision: u64) -> Result<usize, CurationError> {
    let (offset, digest) = value.split_once(':').ok_or(CurationError::InvalidCursor)?;
    if digest != &digest_for_cursor(scope, revision) {
        return Err(CurationError::InvalidCursor);
    }
    offset.parse().map_err(|_| CurationError::InvalidCursor)
}

fn digest(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn digest_for_cursor(scope: &str, revision: u64) -> String {
    digest(&format!("{scope}:{revision}"))[..24].to_owned()
}
