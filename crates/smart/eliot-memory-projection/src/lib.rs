//! Bounded deterministic memory candidate query (#223).
//!
//! [`MemoryCandidateQuery`] selects handles from one already-validated
//! [`MemoryProjectionBatch`] under an explicit [`MemoryKind`] allowlist and a
//! bounded limit. Selection echoes the batch binding and denominator exactly:
//! it never widens scope, never reorders provider order, and fails closed on
//! binding mismatch or an unknown denominator.
//!
//! This is the Smart-side candidate view, not a duplicate of the Governor
//! provider intake: the provider `ProjectionRequest` carries admitted
//! observations for projection, while this query carries only a filter view
//! over an existing batch. The crate emits no applicability verdict, owns no store, index,
//! retrieval, ranking, or promotion authority, and implements no reactive
//! path.

#![forbid(unsafe_code)]

use eliot_contracts::ArtifactId;
use eliot_memory_projection_contracts::{
    DenominatorState, MEMORY_PROJECTION_MAX_RECORDS, MemoryKind, MemoryProjectionBatch,
    MemoryProjectionError, MemoryScopeBinding,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22";

/// Candidate-query failure: every case fails closed with its exact reason.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QueryError {
    /// The supplied batch or binding is invalid upstream.
    #[error("memory candidate query: {0}")]
    Upstream(#[from] MemoryProjectionError),
    /// The batch binding differs from the query binding.
    #[error("memory candidate query: batch binding does not equal the query binding")]
    BindingMismatch,
    /// The batch carries no usable denominator, so coverage is unprovable.
    #[error("memory candidate query: batch denominator is unknown")]
    UnknownDenominator,
    /// The requested limit exceeds the frozen batch bound.
    #[error("memory candidate query: limit {limit} exceeds bound {bound}")]
    LimitOverBound {
        /// Requested candidate limit.
        limit: usize,
        /// Frozen ceiling applied.
        bound: usize,
    },
    /// The kind allowlist is empty: narrowing must be explicit.
    #[error("memory candidate query: kind allowlist is empty")]
    EmptyKinds,
    /// The kind allowlist names one kind twice.
    #[error("memory candidate query: duplicate kind {kind:?}")]
    DuplicateKind {
        /// Repeated kind.
        kind: MemoryKind,
    },
}

/// Bounded candidate query over one frozen projection batch.
///
/// `kinds` is an explicit allowlist: only records whose [`MemoryKind`] it
/// names are selected. `limit` caps the selected candidates and never exceeds
/// [`MEMORY_PROJECTION_MAX_RECORDS`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryCandidateQuery {
    /// Binding the selected batch must carry exactly.
    pub binding: MemoryScopeBinding,
    /// Maximum candidates selected, in deterministic provider order.
    pub limit: usize,
    /// Explicit kind allowlist; empty is rejected.
    pub kinds: Vec<MemoryKind>,
}

impl MemoryCandidateQuery {
    /// Construct a validated query.
    pub fn new(
        binding: MemoryScopeBinding,
        limit: usize,
        kinds: Vec<MemoryKind>,
    ) -> Result<Self, QueryError> {
        let query = Self {
            binding,
            limit,
            kinds,
        };
        query.validate()?;
        Ok(query)
    }

    /// Validate binding shape, limit bound, and allowlist shape.
    pub fn validate(&self) -> Result<(), QueryError> {
        self.binding.validate()?;
        if self.limit == 0 || self.limit > MEMORY_PROJECTION_MAX_RECORDS {
            return Err(QueryError::LimitOverBound {
                limit: self.limit,
                bound: MEMORY_PROJECTION_MAX_RECORDS,
            });
        }
        if self.kinds.is_empty() {
            return Err(QueryError::EmptyKinds);
        }
        let mut seen = std::collections::BTreeSet::new();
        for kind in &self.kinds {
            if !seen.insert(*kind) {
                return Err(QueryError::DuplicateKind { kind: *kind });
            }
        }
        Ok(())
    }
}

/// One selected candidate: handle plus its preserved kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryCandidateRef {
    /// Exact canonical handle of the selected record.
    pub handle: ArtifactId,
    /// Canonical kind of the selected record.
    pub kind: MemoryKind,
}

/// Candidate snapshot over one validated batch.
///
/// The snapshot echoes the batch binding and denominator exactly and
/// preserves deterministic provider order. `truncated` is true when the
/// batch was already truncated or when `limit` cut the selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryCandidateSnapshot {
    /// Binding echoed from the selected batch.
    pub binding: MemoryScopeBinding,
    /// Selected candidates in deterministic provider order.
    pub candidates: Vec<MemoryCandidateRef>,
    /// Denominator total echoed from the selected batch.
    pub denominator_total: usize,
    /// Whether the candidate view is lossy.
    pub truncated: bool,
    /// Revalidation requirement echoed from the selected batch.
    pub revalidation_required: bool,
}

/// Select candidates from a validated batch under the query.
///
/// Fails closed when the query or batch is invalid, when the batch binding
/// differs from the query binding, or when the batch denominator is unknown.
pub fn select(
    query: &MemoryCandidateQuery,
    batch: &MemoryProjectionBatch,
) -> Result<MemoryCandidateSnapshot, QueryError> {
    query.validate()?;
    batch.validate()?;
    if batch.binding != query.binding {
        return Err(QueryError::BindingMismatch);
    }
    let denominator_total = match batch.coverage.denominator {
        DenominatorState::Known { total } => total,
        DenominatorState::Unknown { .. } => return Err(QueryError::UnknownDenominator),
    };
    let mut candidates = Vec::new();
    let mut cut = false;
    for record in &batch.records {
        if !query.kinds.contains(&record.kind) {
            continue;
        }
        if candidates.len() >= query.limit {
            cut = true;
            break;
        }
        candidates.push(MemoryCandidateRef {
            handle: record.handle.clone(),
            kind: record.kind,
        });
    }
    Ok(MemoryCandidateSnapshot {
        binding: batch.binding.clone(),
        candidates,
        denominator_total,
        truncated: batch.coverage.truncated || cut,
        revalidation_required: batch.coverage.revalidation_required,
    })
}
