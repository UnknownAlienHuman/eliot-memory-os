//! Owner query intent, selection policy, and selection trace (CC-MEMORY-PROJECTION-SCHEMA).
//!
//! [`MemoryQueryIntent`] states what a caller wants narrowed from one
//! [`MemoryProjectionBatch`]: the binding the batch must carry, an explicit
//! [`MemoryKind`] allowlist, and a bounded limit. [`MemorySelectionPolicy`]
//! carries the enforceable ceiling one selection may emit. [`select`]
//! consumes the batch whole and emits a [`MemorySelectionTrace`] with one
//! entry per batch record in deterministic provider order.
//!
//! Selection narrows; it never verdicts. Records outside the allowlist are
//! recorded as [`SelectionDisposition::NotSelected`] with
//! [`ExclusionReason::Rejected`]. That reason has a narrow,
//! trace-local meaning defined by this contract unit: rejected by the
//! explicit caller allowlist recorded in this trace. It is NOT a governed
//! applicability verdict, and it is distinguished from one by the entry
//! type: selection entries never enter [`ApplicableMemorySet`], and the
//! batch still flows whole to `evaluate_applicability`, which remains the
//! sole verdict authority and still verdicts every record independently.
//!
//! The trace denominator ([`SelectionCoverage`]) counts exactly the records
//! presented to selection. It is a different type with different field names
//! from the batch denominator on purpose: the original batch denominator is
//! never echoed under a filtered set, so intentional kind selection can
//! never be mistaken for unaccounted loss.
//!
//! This module is a static selection record. It performs no retrieval,
//! ranking, storage access, or promotion, and it is not edge, product, or
//! W9-consumer proof.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::MemoryProjectionError;
use crate::record::{MemoryKind, MemoryScopeBinding};
use crate::{CONTRACT_VERSION, MemoryProjectionBatch};

/// Selection failure: every case fails closed with its exact reason.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SelectionError {
    /// The intent, policy, or batch shape is invalid upstream.
    #[error("memory selection: {0}")]
    Upstream(#[from] MemoryProjectionError),
    /// The intent binding differs from the batch binding.
    #[error("memory selection: intent binding does not equal the batch binding")]
    BindingMismatch,
    /// The requested limit exceeds the enforced policy ceiling.
    #[error("memory selection: limit {limit} exceeds policy ceiling {ceiling}")]
    LimitOverPolicy {
        /// Requested selection limit.
        limit: usize,
        /// Enforced ceiling.
        ceiling: usize,
    },
    /// More records pass the allowlist than the limit admits. The caller
    /// narrows kinds or raises the limit; selection never cuts silently.
    #[error("memory selection: {passing} records pass the allowlist but the limit admits {limit}")]
    LimitExceeded {
        /// Records passing the allowlist.
        passing: usize,
        /// Requested selection limit.
        limit: usize,
    },
    /// The kind allowlist is empty: narrowing must be explicit.
    #[error("memory selection: kind allowlist is empty")]
    EmptyKinds,
    /// The kind allowlist names one kind twice.
    #[error("memory selection: duplicate kind {kind:?}")]
    DuplicateKind {
        /// Repeated kind.
        kind: MemoryKind,
    },
    /// A limit or ceiling is zero or exceeds the frozen batch bound.
    #[error("memory selection: bound {bound} violated by value {value}")]
    BoundViolated {
        /// Value at fault.
        value: usize,
        /// Frozen ceiling applied.
        bound: usize,
    },
}

/// Owner query intent: what to narrow from one frozen projection batch.
///
/// `kinds` is an explicit allowlist with at least one entry. `limit` caps
/// the selected records and never exceeds
/// [`MEMORY_PROJECTION_MAX_RECORDS`](crate::MEMORY_PROJECTION_MAX_RECORDS).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryQueryIntent {
    /// Contract version this intent was written against.
    pub contract_version: eliot_contracts::ContractVersion,
    /// Binding the selected batch must carry exactly.
    pub binding: MemoryScopeBinding,
    /// Explicit kind allowlist; empty is rejected.
    pub kinds: Vec<MemoryKind>,
    /// Maximum selected records, in deterministic provider order.
    pub limit: usize,
}

impl MemoryQueryIntent {
    /// Construct a validated intent.
    pub fn new(
        binding: MemoryScopeBinding,
        kinds: Vec<MemoryKind>,
        limit: usize,
    ) -> Result<Self, SelectionError> {
        let intent = Self {
            contract_version: CONTRACT_VERSION,
            binding,
            kinds,
            limit,
        };
        intent.validate()?;
        Ok(intent)
    }

    /// Validate version, binding shape, allowlist shape, and limit bound.
    pub fn validate(&self) -> Result<(), SelectionError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(SelectionError::Upstream(
                MemoryProjectionError::VersionMismatch,
            ));
        }
        self.binding.validate()?;
        if self.kinds.is_empty() {
            return Err(SelectionError::EmptyKinds);
        }
        let mut seen = BTreeSet::new();
        for kind in &self.kinds {
            if !seen.insert(*kind) {
                return Err(SelectionError::DuplicateKind { kind: *kind });
            }
        }
        if self.limit == 0 || self.limit > crate::MEMORY_PROJECTION_MAX_RECORDS {
            return Err(SelectionError::BoundViolated {
                value: self.limit,
                bound: crate::MEMORY_PROJECTION_MAX_RECORDS,
            });
        }
        Ok(())
    }
}

/// Owner selection policy: the enforceable ceiling one selection may emit.
///
/// The policy carries no allowlist and no request state; it bounds the
/// caller. A policy ceiling above the frozen batch bound is rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemorySelectionPolicy {
    /// Contract version this policy was written against.
    pub contract_version: eliot_contracts::ContractVersion,
    /// Ceiling on records one selection may emit.
    pub max_selected: usize,
}

impl MemorySelectionPolicy {
    /// Construct a validated policy.
    pub fn new(max_selected: usize) -> Result<Self, SelectionError> {
        let policy = Self {
            contract_version: CONTRACT_VERSION,
            max_selected,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate version and ceiling bound.
    pub fn validate(&self) -> Result<(), SelectionError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(SelectionError::Upstream(
                MemoryProjectionError::VersionMismatch,
            ));
        }
        if self.max_selected == 0 || self.max_selected > crate::MEMORY_PROJECTION_MAX_RECORDS {
            return Err(SelectionError::BoundViolated {
                value: self.max_selected,
                bound: crate::MEMORY_PROJECTION_MAX_RECORDS,
            });
        }
        Ok(())
    }
}

/// Per-record selection disposition.
///
/// `NotSelected` carries [`ExclusionReason::Rejected`] with the narrow
/// trace-local meaning defined above: rejected by the explicit caller
/// allowlist recorded in this trace. Selection entries are a different
/// type from applicability exclusions, so the two `Rejected` meanings
/// cannot merge on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "disposition", deny_unknown_fields)]
pub enum SelectionDisposition {
    /// The record passed the allowlist and is selected.
    #[serde(rename = "SELECTED")]
    Selected,
    /// The record fell outside the allowlist.
    #[serde(rename = "NOT_SELECTED")]
    NotSelected {
        /// Always [`ExclusionReason::Rejected`] with trace-local meaning.
        reason: crate::ExclusionReason,
    },
}

/// One trace entry per batch record, in deterministic provider order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionEntry {
    /// Exact canonical handle of the considered record.
    pub handle: ArtifactId,
    /// Canonical kind of the considered record.
    pub kind: MemoryKind,
    /// Selection outcome for this record.
    pub disposition: SelectionDisposition,
}

/// Selection denominator: exactly the records presented to selection.
///
/// This is intentionally a different type from the batch denominator:
/// `considered` counts presented records, `selected` plus `not_selected`
/// always equals `considered`, and no batch total is echoed here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionCoverage {
    /// Batch records presented to selection.
    pub considered: usize,
    /// Entries with [`SelectionDisposition::Selected`].
    pub selected: usize,
    /// Entries with [`SelectionDisposition::NotSelected`].
    pub not_selected: usize,
}

/// Trace of one selection over one whole batch.
///
/// The trace binds the intent that produced it through `intent_digest`
/// (sha256 over the canonical intent bytes) and echoes the allowlist so
/// the narrowing stays recheckable without the intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemorySelectionTrace {
    /// Contract version this trace was written against.
    pub contract_version: eliot_contracts::ContractVersion,
    /// Binding echoed from the intent, equal to the batch binding.
    pub binding: MemoryScopeBinding,
    /// Allowlist echoed from the intent.
    pub allowlist: Vec<MemoryKind>,
    /// Canonical digest of the intent that produced this trace.
    pub intent_digest: String,
    /// Policy ceiling echoed from the policy that bounded this trace.
    /// Auditors recheck `selected <= policy_ceiling` without the policy.
    pub policy_ceiling: usize,
    /// One entry per batch record, in deterministic provider order.
    pub entries: Vec<SelectionEntry>,
    /// Selection denominator over exactly the presented records.
    pub coverage: SelectionCoverage,
}

impl MemorySelectionTrace {
    /// Validate version, binding, digest shape, entry accounting, and the
    /// selection denominator.
    pub fn validate(&self) -> Result<(), SelectionError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(SelectionError::Upstream(
                MemoryProjectionError::VersionMismatch,
            ));
        }
        self.binding.validate()?;
        if self.allowlist.is_empty() {
            return Err(SelectionError::EmptyKinds);
        }
        if self.intent_digest.len() != 64
            || !self
                .intent_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(SelectionError::Upstream(
                MemoryProjectionError::InvalidField {
                    field: "trace.intent_digest",
                    reason: "must be 64 lowercase hex characters",
                },
            ));
        }
        if self.policy_ceiling == 0 || self.policy_ceiling > crate::MEMORY_PROJECTION_MAX_RECORDS {
            return Err(SelectionError::BoundViolated {
                value: self.policy_ceiling,
                bound: crate::MEMORY_PROJECTION_MAX_RECORDS,
            });
        }
        let mut selected = 0usize;
        let mut not_selected = 0usize;
        for entry in &self.entries {
            match &entry.disposition {
                SelectionDisposition::Selected => {
                    selected += 1;
                    if !self.allowlist.contains(&entry.kind) {
                        return Err(SelectionError::Upstream(
                            MemoryProjectionError::InvalidField {
                                field: "trace.entries",
                                reason: "selected kind is outside the echoed allowlist",
                            },
                        ));
                    }
                }
                SelectionDisposition::NotSelected { reason } => {
                    not_selected += 1;
                    if *reason != crate::ExclusionReason::Rejected {
                        return Err(SelectionError::Upstream(
                            MemoryProjectionError::InvalidField {
                                field: "trace.entries",
                                reason: "selection exclusion must carry Rejected",
                            },
                        ));
                    }
                }
            }
        }
        if self.coverage.considered != self.entries.len()
            || self.coverage.selected != selected
            || self.coverage.not_selected != not_selected
        {
            return Err(SelectionError::Upstream(
                MemoryProjectionError::CoverageMismatch {
                    reason: "selection coverage must account every entry exactly",
                },
            ));
        }
        if self.coverage.selected > self.policy_ceiling {
            return Err(SelectionError::Upstream(
                MemoryProjectionError::CoverageMismatch {
                    reason: "selected exceeds the echoed policy ceiling",
                },
            ));
        }
        // The batch denominator is never echoed here by construction: this
        // type has no field for it.
        Ok(())
    }
}

/// Select from one whole batch under an intent and policy, emitting a trace.
///
/// The batch is validated and consumed whole; the intent binding must equal
/// the batch binding. Records in the allowlist are selected up to the
/// limit; records outside it are recorded as not selected. More passing
/// records than the limit admits fails closed with [`SelectionError::LimitExceeded`];
/// selection never cuts silently and never reorders provider order.
///
/// The trace binds all three governors: the intent through `intent_digest`,
/// the policy through the echoed `policy_ceiling` (recheckable as
/// `selected <= policy_ceiling` without the policy), and the batch
/// structurally (one entry per batch record in provider order under the
/// checked binding equality; batches carry no digest field to echo).
///
/// The returned trace is fully validated. It is a static selection record,
/// not an applicability verdict and not edge, product, or W9-consumer
/// proof: forward the untouched batch to `evaluate_applicability` for the
/// verdict.
pub fn select(
    intent: &MemoryQueryIntent,
    policy: &MemorySelectionPolicy,
    batch: &MemoryProjectionBatch,
) -> Result<MemorySelectionTrace, SelectionError> {
    intent.validate()?;
    policy.validate()?;
    batch.validate()?;
    if intent.binding != batch.binding {
        return Err(SelectionError::BindingMismatch);
    }
    if intent.limit > policy.max_selected {
        return Err(SelectionError::LimitOverPolicy {
            limit: intent.limit,
            ceiling: policy.max_selected,
        });
    }
    // The batch denominator is read, never echoed: selection claims only
    // the presented set. An unknown batch denominator stays selectable
    // because narrowing claims no completeness.
    let _ = &batch.coverage.denominator;
    let passing = passing_count(batch, &intent.kinds);
    if passing > intent.limit {
        return Err(SelectionError::LimitExceeded {
            passing,
            limit: intent.limit,
        });
    }
    let mut entries = Vec::new();
    for record in &batch.records {
        if intent.kinds.contains(&record.kind) {
            entries.push(SelectionEntry {
                handle: record.handle.clone(),
                kind: record.kind,
                disposition: SelectionDisposition::Selected,
            });
        } else {
            entries.push(SelectionEntry {
                handle: record.handle.clone(),
                kind: record.kind,
                disposition: SelectionDisposition::NotSelected {
                    reason: crate::ExclusionReason::Rejected,
                },
            });
        }
    }
    let selected = entries
        .iter()
        .filter(|entry| matches!(entry.disposition, SelectionDisposition::Selected))
        .count();
    let trace = MemorySelectionTrace {
        contract_version: CONTRACT_VERSION,
        binding: intent.binding.clone(),
        allowlist: intent.kinds.clone(),
        intent_digest: intent_digest(intent)?,
        policy_ceiling: policy.max_selected,
        entries,
        coverage: SelectionCoverage {
            considered: batch.records.len(),
            selected,
            not_selected: batch.records.len() - selected,
        },
    };
    trace.validate()?;
    Ok(trace)
}

/// Count records passing the allowlist, in provider order.
fn passing_count(batch: &MemoryProjectionBatch, kinds: &[MemoryKind]) -> usize {
    batch
        .records
        .iter()
        .filter(|record| kinds.contains(&record.kind))
        .count()
}

/// Canonical digest binding a trace to its intent.
fn intent_digest(intent: &MemoryQueryIntent) -> Result<String, SelectionError> {
    canonical_json_bytes(intent)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| {
            SelectionError::Upstream(MemoryProjectionError::InvalidField {
                field: "intent.digest",
                reason: "intent is not canonically encodable",
            })
        })
}
