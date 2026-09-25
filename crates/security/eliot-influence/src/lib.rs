//! The single policy owner for origin-bound influence.
//!
//! This crate evaluates immutable provenance and source-assurance records.  It
//! does not persist content or perform a purge.  Callers must persist the
//! returned receipt and use its explicit closure when updating derived state.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::{
    EpistemicUse, InfluenceDependencyClosure, InfluenceState, RevocationReason, SourceAssurance,
};
use schemars::JsonSchema;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.security.influence";
pub const CONTRACT_VERSION: &str = "eliot-influence-v1";

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceLevel {
    Stored,
    Available,
    Delivered,
    Acknowledged,
    Used,
    VerifiedUse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRecord {
    pub subject_ref: String,
    pub origin_ref: String,
    pub source_assurance: SourceAssurance,
    pub parent_refs: Vec<String>,
    pub transformation_ref: Option<String>,
    pub state_fence: StateFence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Public policy wire shape intentionally retains independent boolean gates.
#[allow(clippy::struct_excessive_bools)]
pub struct InfluencePolicy {
    pub policy_id: String,
    pub revision: u64,
    pub state_fence: StateFence,
    pub require_verified_integrity: bool,
    pub require_current_freshness: bool,
    pub allow_unknown_independence: bool,
    pub allow_instruction_taint: bool,
    pub minimum_level: InfluenceLevel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluenceRequest {
    pub request_id: String,
    pub subject_ref: String,
    pub requested_level: InfluenceLevel,
    pub policy: InfluencePolicy,
    pub provenance: ProvenanceRecord,
    pub dependency_closure: InfluenceDependencyClosure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceDisposition {
    Allowed,
    Restricted,
    Quarantined,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluenceDecision {
    pub request_id: String,
    pub request_digest: String,
    pub subject_ref: String,
    pub disposition: InfluenceDisposition,
    pub allowed_level: InfluenceLevel,
    pub reasons: Vec<InfluenceReason>,
    pub origin_ref: String,
    pub policy_id: String,
    pub state_fence: StateFence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceReason {
    IntegrityNotVerified,
    SourceStale,
    SourceQuarantined,
    SourceUnknown,
    InstructionTainted,
    WrongScope,
    DependencyRevoked,
    DependencyQuarantined,
    IncompleteLineage,
    PolicyFenceMismatch,
    RequestedLevelCapped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationRequest {
    pub request_id: String,
    pub root_ref: String,
    pub reason: RevocationReason,
    pub state_fence: StateFence,
    pub graph: Vec<InfluenceEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluenceEdge {
    pub source_ref: String,
    pub dependent_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationReceipt {
    pub request_id: String,
    pub request_digest: String,
    pub root_ref: String,
    pub affected_refs: Vec<String>,
    pub closures: Vec<InfluenceDependencyClosure>,
    pub state_fence: StateFence,
}

impl InfluencePolicy {
    pub fn validate(&self) -> Result<(), InfluenceError> {
        text(&self.policy_id, "policy_id")?;
        self.state_fence
            .validate()
            .map_err(|_| InfluenceError::InvalidField("state_fence"))?;
        Ok(())
    }
}

impl InfluenceRequest {
    pub fn validate(&self) -> Result<(), InfluenceError> {
        text(&self.request_id, "request_id")?;
        text(&self.subject_ref, "subject_ref")?;
        self.policy.validate()?;
        self.provenance.validate()?;
        self.dependency_closure
            .validate()
            .map_err(|_| InfluenceError::InvalidClosure)?;
        if self.provenance.subject_ref != self.subject_ref
            || self.dependency_closure.root_ref != self.provenance.origin_ref
            || self.provenance.state_fence != self.policy.state_fence
            || self.dependency_closure.state_fence != self.policy.state_fence
        {
            return Err(InfluenceError::FenceOrLineageMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, InfluenceError> {
        self.validate()?;
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceError::Canonicalization)
    }
}

impl ProvenanceRecord {
    pub fn validate(&self) -> Result<(), InfluenceError> {
        text(&self.subject_ref, "provenance.subject_ref")?;
        text(&self.origin_ref, "provenance.origin_ref")?;
        self.source_assurance
            .validate()
            .map_err(|_| InfluenceError::InvalidSourceAssurance)?;
        self.state_fence
            .validate()
            .map_err(|_| InfluenceError::InvalidField("provenance.state_fence"))?;
        unique(&self.parent_refs, "parent_refs")?;
        if let Some(reference) = &self.transformation_ref {
            text(reference, "transformation_ref")?;
        }
        if self.source_assurance.state_fence != self.state_fence {
            return Err(InfluenceError::FenceOrLineageMismatch);
        }
        Ok(())
    }
}

/// Mixed-lineage influence ceiling (I12.20 S3).
///
/// A derived item with more than one material supporting source (`parent_refs`)
/// inherits the minimum allowed influence across those sources. The wire shape
/// carries one assurance, one policy minimum, and one dependency closure, so
/// the minimum is taken across every locally material allowance: the
/// candidate level, the requested level, the policy minimum, and the closure
/// ceiling (`Stored` unless the closure is `Active`). Single-lineage items
/// pass through unchanged.
#[must_use]
pub fn minimum_allowed_influence(
    request: &InfluenceRequest,
    candidate: InfluenceLevel,
) -> InfluenceLevel {
    if request.provenance.parent_refs.len() <= 1 {
        return candidate;
    }
    let closure_ceiling = match request.dependency_closure.current_influence {
        InfluenceState::Active => InfluenceLevel::VerifiedUse,
        InfluenceState::Quarantined | InfluenceState::Revoked | InfluenceState::Unknown => {
            InfluenceLevel::Stored
        }
    };
    candidate
        .min(request.requested_level)
        .min(request.policy.minimum_level)
        .min(closure_ceiling)
}

pub fn decide(request: &InfluenceRequest) -> Result<InfluenceDecision, InfluenceError> {
    let digest = request.digest()?;
    let source = &request.provenance.source_assurance;
    let mut reasons = Vec::new();
    if request.dependency_closure.current_influence == InfluenceState::Revoked {
        reasons.push(InfluenceReason::DependencyRevoked);
    } else if request.dependency_closure.current_influence == InfluenceState::Quarantined {
        reasons.push(InfluenceReason::DependencyQuarantined);
    } else if request.dependency_closure.current_influence == InfluenceState::Unknown {
        // Fail-closed: an unknown dependency state proves nothing, so it
        // quarantines like an explicit quarantine instead of allowing use.
        reasons.push(InfluenceReason::DependencyQuarantined);
    }
    if request.policy.require_verified_integrity
        && !matches!(
            source.integrity,
            eliot_security_contracts::IntegrityStatus::Verified
        )
    {
        reasons.push(InfluenceReason::IntegrityNotVerified);
    }
    if request.policy.require_current_freshness
        && !matches!(
            source.freshness,
            eliot_security_contracts::FreshnessStatus::Current
        )
    {
        reasons.push(InfluenceReason::SourceStale);
    }
    if !matches!(
        source.quarantine,
        eliot_security_contracts::QuarantineState::None
            | eliot_security_contracts::QuarantineState::Released
    ) {
        reasons.push(InfluenceReason::SourceQuarantined);
    }
    if !request.policy.allow_instruction_taint
        && source.instruction_taint != eliot_security_contracts::InstructionTaint::Cleared
    {
        reasons.push(InfluenceReason::InstructionTainted);
    }
    if !request.policy.allow_unknown_independence
        && matches!(
            source.independence,
            eliot_security_contracts::IndependenceLevel::Unknown
        )
    {
        reasons.push(InfluenceReason::SourceUnknown);
    }
    if request.provenance.parent_refs.is_empty() && request.provenance.transformation_ref.is_some()
    {
        reasons.push(InfluenceReason::IncompleteLineage);
    }
    let blocked = reasons.iter().any(|reason| {
        matches!(
            reason,
            InfluenceReason::DependencyRevoked
                | InfluenceReason::DependencyQuarantined
                | InfluenceReason::SourceQuarantined
                | InfluenceReason::WrongScope
        )
    });
    let restricted = !reasons.is_empty();
    let baseline_level = if blocked {
        InfluenceLevel::Stored
    } else if restricted {
        InfluenceLevel::Available.min(request.policy.minimum_level)
    } else {
        request.requested_level.min(request.policy.minimum_level)
    };
    let allowed_level = minimum_allowed_influence(request, baseline_level);
    if allowed_level != request.requested_level {
        reasons.push(InfluenceReason::RequestedLevelCapped);
    }
    let disposition = if reasons
        .iter()
        .any(|reason| matches!(reason, InfluenceReason::DependencyRevoked))
    {
        InfluenceDisposition::Revoked
    } else if blocked {
        InfluenceDisposition::Quarantined
    } else if restricted {
        InfluenceDisposition::Restricted
    } else {
        InfluenceDisposition::Allowed
    };
    Ok(InfluenceDecision {
        request_id: request.request_id.clone(),
        request_digest: digest,
        subject_ref: request.subject_ref.clone(),
        disposition,
        allowed_level,
        reasons,
        origin_ref: request.provenance.origin_ref.clone(),
        policy_id: request.policy.policy_id.clone(),
        state_fence: request.policy.state_fence.clone(),
    })
}

/// Traverse the explicit influence dependency closure (I12.20 S1-S2).
///
/// Breadth-first, multi-hop, and cycle-safe over the caller-supplied derived
/// edges: returns every transitively affected handle (root included), sorted
/// and unique — not just the direct dependents. Callers validate edge text
/// before traversal; this engine never mutates its input.
#[must_use]
pub fn traverse_dependency_closure<'a>(root: &'a str, graph: &'a [InfluenceEdge]) -> Vec<String> {
    let mut adjacency: BTreeMap<&'a str, Vec<&'a str>> = BTreeMap::new();
    for edge in graph {
        adjacency
            .entry(edge.source_ref.as_str())
            .or_default()
            .push(edge.dependent_ref.as_str());
    }
    let mut affected = BTreeSet::new();
    let mut queue = VecDeque::from([root]);
    while let Some(reference) = queue.pop_front() {
        if !affected.insert(reference.to_owned()) {
            continue;
        }
        if let Some(dependents) = adjacency.get(reference) {
            queue.extend(dependents.iter().copied());
        }
    }
    affected.into_iter().collect()
}

pub fn revoke(request: &RevocationRequest) -> Result<RevocationReceipt, InfluenceError> {
    text(&request.request_id, "request_id")?;
    text(&request.root_ref, "root_ref")?;
    request
        .state_fence
        .validate()
        .map_err(|_| InfluenceError::InvalidField("state_fence"))?;
    for edge in &request.graph {
        text(&edge.source_ref, "edge.source_ref")?;
        text(&edge.dependent_ref, "edge.dependent_ref")?;
    }
    let affected_refs = traverse_dependency_closure(request.root_ref.as_str(), &request.graph);
    let closures = affected_refs
        .iter()
        .map(|subject| InfluenceDependencyClosure {
            closure_id: format!("{}:{}", request.request_id, subject),
            root_ref: request.root_ref.clone(),
            dependent_refs: affected_refs.clone(),
            invalidation_reason: Some(request.reason),
            current_influence: InfluenceState::Revoked,
            state_fence: request.state_fence.clone(),
            revision: 0,
        })
        .collect::<Vec<_>>();
    for closure in &closures {
        closure
            .validate()
            .map_err(|_| InfluenceError::InvalidClosure)?;
    }
    let request_digest = canonical_json_bytes(request)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| InfluenceError::Canonicalization)?;
    Ok(RevocationReceipt {
        request_id: request.request_id.clone(),
        request_digest,
        root_ref: request.root_ref.clone(),
        affected_refs,
        closures,
        state_fence: request.state_fence.clone(),
    })
}

// ---------------------------------------------------------------------------
// Issue 686: bounded transitive revocation engine.
//
// The unbounded [`revoke`] traversal above follows every caller-supplied edge
// with a function-local visited set. The bounded engine below is the only
// Issue-686 revocation path: it traverses an explicit, caller-qualified edge
// set under independent node/edge/depth/result/work limits, with an
// operation-global visited set that includes resumed pages. Only
// [`InfluenceEdgeDisposition::PermittedCurrent`] edges propagate; every other
// disposition is recorded as an omission and never traversed. A `PARTIAL`
// denominator never yields a clear outcome: it is rejected with
// [`InfluenceError::UnknownCompleteness`].
// ---------------------------------------------------------------------------

/// Denominator completeness of the caller-supplied edge closure.
///
/// `COMPLETE` asserts the caller supplied the full closure; `PARTIAL` admits
/// the denominator is incomplete and can never produce a clear outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClosureCompleteness {
    Complete,
    Partial,
}

/// Caller-stated disposition of one influence edge.
///
/// Only `PERMITTED_CURRENT` edges propagate revocation. Every other
/// disposition is recorded as an omission and never traversed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceEdgeDisposition {
    PermittedCurrent,
    Quarantined,
    NonPropagating,
    Stale,
    Invalidated,
    CrossScope,
}

/// One caller-qualified influence edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualifiedInfluenceEdge {
    pub source_ref: String,
    pub dependent_ref: String,
    pub disposition: InfluenceEdgeDisposition,
}

/// Independent traversal limits for [`revoke_bounded`].
///
/// Each bound gates a distinct resource: admitted nodes, examined edges,
/// traversal depth, emitted results, and cumulative work (edge examinations
/// plus node admissions).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationBounds {
    pub max_nodes: u64,
    pub max_edges: u64,
    pub max_depth: u64,
    pub max_result: u64,
    pub max_work: u64,
}

impl RevocationBounds {
    /// Default traversal limits for the bounded revocation engine.
    pub fn default_bounds() -> Self {
        Self {
            max_nodes: 4096,
            max_edges: 8192,
            max_depth: 64,
            max_result: 4096,
            max_work: 65536,
        }
    }

    /// Reject a bounds set with any zero limit.
    pub fn validate(&self) -> Result<(), InfluenceError> {
        if self.max_nodes == 0 {
            return Err(InfluenceError::InvalidField("bounds.max_nodes"));
        }
        if self.max_edges == 0 {
            return Err(InfluenceError::InvalidField("bounds.max_edges"));
        }
        if self.max_depth == 0 {
            return Err(InfluenceError::InvalidField("bounds.max_depth"));
        }
        if self.max_result == 0 {
            return Err(InfluenceError::InvalidField("bounds.max_result"));
        }
        if self.max_work == 0 {
            return Err(InfluenceError::InvalidField("bounds.max_work"));
        }
        Ok(())
    }
}

/// Per-call work limits for one page of a bounded revocation.
///
/// These limits bound only the current call. The original operation-global
/// [`RevocationBounds`] remain bound in the continuation and are checked across
/// all pages; increasing a page limit cannot widen the operation ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundedRevocationPageLimits {
    pub max_page_edges: u64,
    pub max_page_work: u64,
}

impl BoundedRevocationPageLimits {
    /// Reject a page that cannot examine even one edge or perform the initial
    /// root admission work unit.
    pub fn validate(&self) -> Result<(), InfluenceError> {
        if self.max_page_edges == 0 {
            return Err(InfluenceError::InvalidField("page_limits.max_page_edges"));
        }
        if self.max_page_work == 0 {
            return Err(InfluenceError::InvalidField("page_limits.max_page_work"));
        }
        Ok(())
    }

    fn all_global_work(bounds: &RevocationBounds) -> Self {
        Self {
            max_page_edges: bounds.max_edges,
            max_page_work: bounds.max_work,
        }
    }
}

/// Why a qualified edge was omitted from a bounded revocation traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OmissionCause {
    BoundsExhausted,
    Quarantined,
    NonPropagating,
    Stale,
    Invalidated,
    CrossScope,
}

/// One edge omitted from a bounded revocation traversal, with its cause.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationOmission {
    pub edge_source: String,
    pub edge_dependent: String,
    pub cause: OmissionCause,
}

/// Bounded revocation request over an explicit qualified edge set.
///
/// `resumed_visited` remains on the wire for source compatibility only.  A
/// nonempty value is refused: a visited list cannot identify unexpanded
/// source-bound edge positions, depths, omissions, or cumulative accounting.
/// Resumption must use [`resume_bounded_revocation`] with the exact
/// [`BoundedRevocationContinuation`] returned by the prior page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundedRevocationRequest {
    pub request_id: String,
    pub root_ref: String,
    pub reason: RevocationReason,
    pub state_fence: StateFence,
    pub edges: Vec<QualifiedInfluenceEdge>,
    pub completeness: ClosureCompleteness,
    pub resumed_visited: Vec<String>,
}

/// Stable schema identity for a bounded-revocation continuation.
///
/// A continuation is a continuation of one operation, not a new traversal
/// rooted at `root_ref`.  The value is deliberately explicit so a serialized
/// continuation can be rejected when its schema is not understood.
pub const BOUNDED_REVOCATION_CONTINUATION_SCHEMA: &str = "eliot-bounded-revocation-continuation-v1";

/// An admitted node and the depth at which it was first discovered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundedRevocationPendingNode {
    pub node_ref: String,
    pub depth: u64,
}

/// A source-bound edge position retained by a continuation.
///
/// `source_depth` is the depth of `source_ref`, not the depth of the target.
/// Keeping the position, rather than only a target string, is what prevents a
/// resumed operation from silently skipping the rest of a node's adjacency
/// list.  `disposition` is copied from the exact qualified-edge snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundedRevocationPendingEdge {
    pub source_ref: String,
    pub dependent_ref: String,
    pub source_depth: u64,
    pub disposition: InfluenceEdgeDisposition,
}

/// Explicit, source-bound continuation state for a bounded revocation.
///
/// The continuation is the authority-bearing position of the original
/// operation.  It is not a visited-only hint: admitted nodes, fully expanded
/// nodes, unexpanded queue entries, and unexamined edge positions are kept
/// separately.  All identities are checked by
/// [`resume_bounded_revocation`] before traversal resumes.
///
/// `admitted_nodes` is the depth-bearing form of `admitted_refs`.  The
/// separate `examined_edges` and `pending_edges` vectors make the edge
/// partition auditable and prevent a caller from fabricating completeness by
/// omitting an edge from a continuation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundedRevocationContinuation {
    pub schema_version: String,
    pub request_id: String,
    pub root_ref: String,
    pub reason: RevocationReason,
    pub completeness: ClosureCompleteness,
    pub request_digest: String,
    pub graph_snapshot_digest: String,
    pub state_fence: StateFence,
    pub bounds_digest: String,
    pub admitted_refs: Vec<String>,
    pub admitted_nodes: Vec<BoundedRevocationPendingNode>,
    pub expanded_refs: Vec<String>,
    /// Canonical pending queue order: node reference, then depth.
    pub pending: Vec<BoundedRevocationPendingNode>,
    pub pending_edges: Vec<BoundedRevocationPendingEdge>,
    pub examined_edges: Vec<BoundedRevocationPendingEdge>,
    pub edges_examined: u64,
    pub work_spent: u64,
    pub omissions: Vec<RevocationOmission>,
    pub frontier: Vec<String>,
    pub previous_page_exhausted: bool,
    /// SHA-256 over every other continuation field. Resume rejects any
    /// mismatch before using queue, edge, counter, omission, or frontier state.
    pub continuation_digest: String,
}

impl BoundedRevocationContinuation {
    /// Digest the complete continuation with the canonical JSON encoding,
    /// excluding the digest field itself.
    pub fn digest(&self) -> Result<String, InfluenceError> {
        let mut view = self.clone();
        view.continuation_digest.clear();
        canonical_digest(&view)
    }
}

/// Opaque capability emitted with a live continuation.
///
/// The digest field is intentionally private: a caller can carry the token
/// returned by the preceding page, but cannot mint a token for a fabricated
/// continuation. A deserialized wire outcome has no live token and must be
/// re-admitted by its owning persistence boundary before resume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedRevocationContinuationToken {
    digest: String,
}

impl BoundedRevocationContinuationToken {
    fn digest(&self) -> &str {
        &self.digest
    }
}

/// Bounded revocation outcome.
///
/// `affected_refs` always contains the root. `complete` is false whenever any
/// bound was exhausted; non-bound omissions never clear completeness.
/// `frontier` is the current unresolved source-bound frontier (empty after a
/// complete resume), and `omissions` records every cumulative omitted edge.
/// `work_spent` accumulates edge
/// examinations plus node admissions across every page of the operation.
///
/// `continuation` is present whenever the operation is not a complete
/// one-shot traversal. The wire field itself is required (use `null` for a
/// complete outcome); an omitted field is rejected. In particular, an
/// exhausted page retains its entire unexpanded queue and every unexamined
/// edge position; it is never converted into a successful result merely
/// because the page ended.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
pub struct BoundedRevocationOutcome {
    pub root_ref: String,
    pub affected_refs: Vec<String>,
    pub frontier: Vec<String>,
    pub omissions: Vec<RevocationOmission>,
    pub work_spent: u64,
    pub complete: bool,
    pub continuation: Option<BoundedRevocationContinuation>,
    #[serde(skip)]
    continuation_token: Option<BoundedRevocationContinuationToken>,
}

impl BoundedRevocationOutcome {
    /// Return the live continuation capability emitted with this outcome.
    pub fn continuation_token(&self) -> Option<&BoundedRevocationContinuationToken> {
        self.continuation_token.as_ref()
    }
}

impl<'de> Deserialize<'de> for BoundedRevocationOutcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct OutcomeVisitor;

        impl<'de> Visitor<'de> for OutcomeVisitor {
            type Value = BoundedRevocationOutcome;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a complete bounded revocation outcome")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut root_ref = None;
                let mut affected_refs = None;
                let mut frontier = None;
                let mut omissions = None;
                let mut work_spent = None;
                let mut complete = None;
                let mut continuation: Option<Option<BoundedRevocationContinuation>> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "root_ref" => set_field(&mut root_ref, "root_ref", map.next_value()?)?,
                        "affected_refs" => {
                            set_field(&mut affected_refs, "affected_refs", map.next_value()?)?;
                        }
                        "frontier" => set_field(&mut frontier, "frontier", map.next_value()?)?,
                        "omissions" => set_field(&mut omissions, "omissions", map.next_value()?)?,
                        "work_spent" => {
                            set_field(&mut work_spent, "work_spent", map.next_value()?)?;
                        }
                        "complete" => set_field(&mut complete, "complete", map.next_value()?)?,
                        "continuation" => {
                            set_field(&mut continuation, "continuation", map.next_value()?)?;
                        }
                        _ => return Err(de::Error::unknown_field(&key, &[])),
                    }
                }
                Ok(BoundedRevocationOutcome {
                    root_ref: required(root_ref, "root_ref")?,
                    affected_refs: required(affected_refs, "affected_refs")?,
                    frontier: required(frontier, "frontier")?,
                    omissions: required(omissions, "omissions")?,
                    work_spent: required(work_spent, "work_spent")?,
                    complete: required(complete, "complete")?,
                    continuation: required(continuation, "continuation")?,
                    continuation_token: None,
                })
            }
        }

        fn set_field<T, E>(slot: &mut Option<T>, name: &'static str, value: T) -> Result<(), E>
        where
            E: de::Error,
        {
            if slot.is_some() {
                return Err(E::duplicate_field(name));
            }
            *slot = Some(value);
            Ok(())
        }

        fn required<T, E>(value: Option<T>, name: &'static str) -> Result<T, E>
        where
            E: de::Error,
        {
            value.ok_or_else(|| E::missing_field(name))
        }

        deserializer.deserialize_map(OutcomeVisitor)
    }
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, InfluenceError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| InfluenceError::Canonicalization)
}

const BOUNDED_REVOCATION_REQUEST_IDENTITY_SCHEMA: &str =
    "eliot-bounded-revocation-request-identity-v1";

#[derive(Serialize)]
struct BoundedRequestIdentity<'a> {
    schema_version: &'static str,
    request_id: &'a str,
    root_ref: &'a str,
    reason: &'a RevocationReason,
    state_fence: &'a StateFence,
    completeness: &'a ClosureCompleteness,
    graph_snapshot_digest: &'a str,
}

impl BoundedRevocationRequest {
    /// Return the canonical identity of this valid bounded request.
    ///
    /// Edge order is normalized before hashing, while the independently bound
    /// graph digest preserves the exact qualified-edge multiset. The legacy
    /// `resumed_visited` compatibility field is not part of this identity and
    /// is refused by the bounded engine when nonempty.
    pub fn digest(&self) -> Result<String, InfluenceError> {
        let graph_snapshot_digest = self.graph_snapshot_digest()?;
        canonical_digest(&BoundedRequestIdentity {
            schema_version: BOUNDED_REVOCATION_REQUEST_IDENTITY_SCHEMA,
            request_id: &self.request_id,
            root_ref: &self.root_ref,
            reason: &self.reason,
            state_fence: &self.state_fence,
            completeness: &self.completeness,
            graph_snapshot_digest: &graph_snapshot_digest,
        })
    }

    /// Return the identity of the exact qualified-edge snapshot in canonical
    /// source/dependent/disposition order.
    pub fn graph_snapshot_digest(&self) -> Result<String, InfluenceError> {
        let mut edges = self.edges.clone();
        edges.sort_by(|left, right| {
            (
                left.source_ref.as_str(),
                left.dependent_ref.as_str(),
                edge_disposition_rank(left.disposition),
            )
                .cmp(&(
                    right.source_ref.as_str(),
                    right.dependent_ref.as_str(),
                    edge_disposition_rank(right.disposition),
                ))
        });
        canonical_digest(&edges)
    }
}

impl RevocationBounds {
    /// Return the canonical identity of this exact independent bounds set.
    pub fn digest(&self) -> Result<String, InfluenceError> {
        canonical_digest(self)
    }
}

fn omission_cause_for(disposition: InfluenceEdgeDisposition) -> Option<OmissionCause> {
    match disposition {
        InfluenceEdgeDisposition::PermittedCurrent => None,
        InfluenceEdgeDisposition::Quarantined => Some(OmissionCause::Quarantined),
        InfluenceEdgeDisposition::NonPropagating => Some(OmissionCause::NonPropagating),
        InfluenceEdgeDisposition::Stale => Some(OmissionCause::Stale),
        InfluenceEdgeDisposition::Invalidated => Some(OmissionCause::Invalidated),
        InfluenceEdgeDisposition::CrossScope => Some(OmissionCause::CrossScope),
    }
}

fn omission_cause_rank(cause: OmissionCause) -> u8 {
    match cause {
        OmissionCause::BoundsExhausted => 0,
        OmissionCause::Quarantined => 1,
        OmissionCause::NonPropagating => 2,
        OmissionCause::Stale => 3,
        OmissionCause::Invalidated => 4,
        OmissionCause::CrossScope => 5,
    }
}

fn edge_disposition_rank(disposition: InfluenceEdgeDisposition) -> u8 {
    match disposition {
        InfluenceEdgeDisposition::PermittedCurrent => 0,
        InfluenceEdgeDisposition::Quarantined => 1,
        InfluenceEdgeDisposition::NonPropagating => 2,
        InfluenceEdgeDisposition::Stale => 3,
        InfluenceEdgeDisposition::Invalidated => 4,
        InfluenceEdgeDisposition::CrossScope => 5,
    }
}

#[derive(Clone, Debug)]
struct BoundedBinding {
    request_id: String,
    reason: RevocationReason,
    completeness: ClosureCompleteness,
    request_digest: String,
    graph_snapshot_digest: String,
    bounds_digest: String,
}

fn bounded_binding(
    request: &BoundedRevocationRequest,
    bounds: &RevocationBounds,
) -> Result<BoundedBinding, InfluenceError> {
    Ok(BoundedBinding {
        request_id: request.request_id.clone(),
        reason: request.reason,
        completeness: request.completeness,
        request_digest: request.digest()?,
        graph_snapshot_digest: request.graph_snapshot_digest()?,
        bounds_digest: bounds.digest()?,
    })
}

#[derive(Clone, Debug)]
struct PendingNodeState {
    node_ref: String,
    depth: u64,
    edges: Vec<BoundedRevocationPendingEdge>,
    next_edge: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EdgeBudgetState {
    Fits,
    GlobalExhausted,
    PageExhausted,
}

fn build_adjacency(
    dispositions: &BTreeMap<(String, String), InfluenceEdgeDisposition>,
) -> BTreeMap<String, Vec<BoundedRevocationPendingEdge>> {
    let mut adjacency: BTreeMap<String, Vec<BoundedRevocationPendingEdge>> = BTreeMap::new();
    for ((source_ref, dependent_ref), disposition) in dispositions {
        adjacency
            .entry(source_ref.clone())
            .or_default()
            .push(BoundedRevocationPendingEdge {
                source_ref: source_ref.clone(),
                dependent_ref: dependent_ref.clone(),
                source_depth: 0,
                disposition: *disposition,
            });
    }
    adjacency
}

/// Mutable state of one bounded revocation operation.
///
/// `admitted` is the one operation-global visited set.  It is distinct from
/// `expanded` and from the pending queue: a node can be admitted and still
/// have deterministic edges waiting to be examined.
struct BoundedTraversal {
    bounds: RevocationBounds,
    page_limits: BoundedRevocationPageLimits,
    dispositions: BTreeMap<(String, String), InfluenceEdgeDisposition>,
    adjacency: BTreeMap<String, Vec<BoundedRevocationPendingEdge>>,
    admitted: BTreeMap<String, u64>,
    expanded: BTreeSet<String>,
    frontier: BTreeSet<String>,
    omissions: Vec<RevocationOmission>,
    queue: VecDeque<PendingNodeState>,
    pending_edges: Vec<BoundedRevocationPendingEdge>,
    examined_edges: Vec<BoundedRevocationPendingEdge>,
    edges_examined: u64,
    work_spent: u64,
    page_edges_examined: u64,
    page_work_spent: u64,
    exhausted: bool,
    unresolved_bound: bool,
    request_id: String,
    reason: RevocationReason,
    completeness: ClosureCompleteness,
    request_digest: String,
    graph_snapshot_digest: String,
    bounds_digest: String,
}

impl BoundedTraversal {
    fn new(
        request: &BoundedRevocationRequest,
        bounds: &RevocationBounds,
        page_limits: BoundedRevocationPageLimits,
        dispositions: &BTreeMap<(String, String), InfluenceEdgeDisposition>,
        binding: BoundedBinding,
    ) -> Self {
        let adjacency = build_adjacency(dispositions);
        let mut traversal = Self {
            bounds: bounds.clone(),
            page_limits,
            dispositions: dispositions.clone(),
            adjacency,
            admitted: BTreeMap::new(),
            expanded: BTreeSet::new(),
            frontier: BTreeSet::new(),
            omissions: Vec::new(),
            queue: VecDeque::new(),
            pending_edges: Vec::new(),
            examined_edges: Vec::new(),
            edges_examined: 0,
            work_spent: 1,
            page_edges_examined: 0,
            page_work_spent: 1,
            exhausted: false,
            unresolved_bound: false,
            request_id: binding.request_id,
            reason: binding.reason,
            completeness: binding.completeness,
            request_digest: binding.request_digest,
            graph_snapshot_digest: binding.graph_snapshot_digest,
            bounds_digest: binding.bounds_digest,
        };
        let root = request.root_ref.clone();
        traversal.admitted.insert(root.clone(), 0);
        let root_state = traversal.make_node_state(&root, 0);
        traversal.queue.push_back(root_state);
        traversal
    }

    fn from_continuation(
        bounds: &RevocationBounds,
        page_limits: BoundedRevocationPageLimits,
        dispositions: &BTreeMap<(String, String), InfluenceEdgeDisposition>,
        binding: BoundedBinding,
        continuation: &BoundedRevocationContinuation,
    ) -> Self {
        let adjacency = build_adjacency(dispositions);
        let mut admitted = BTreeMap::new();
        for node in &continuation.admitted_nodes {
            admitted.insert(node.node_ref.clone(), node.depth);
        }
        let pending_by_source: BTreeMap<String, BTreeSet<String>> = continuation
            .pending_edges
            .iter()
            .fold(BTreeMap::new(), |mut sources, edge| {
                sources
                    .entry(edge.source_ref.clone())
                    .or_default()
                    .insert(edge.dependent_ref.clone());
                sources
            });
        let queue: VecDeque<PendingNodeState> = continuation
            .pending
            .iter()
            .map(|pending| {
                let mut state = PendingNodeState {
                    node_ref: pending.node_ref.clone(),
                    depth: pending.depth,
                    edges: adjacency
                        .get(&pending.node_ref)
                        .map(|edges| {
                            edges
                                .iter()
                                .map(|edge| BoundedRevocationPendingEdge {
                                    source_ref: edge.source_ref.clone(),
                                    dependent_ref: edge.dependent_ref.clone(),
                                    source_depth: pending.depth,
                                    disposition: edge.disposition,
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                    next_edge: 0,
                };
                if let Some(targets) = pending_by_source.get(&pending.node_ref) {
                    state.next_edge = state
                        .edges
                        .iter()
                        .position(|edge| targets.contains(&edge.dependent_ref))
                        .unwrap_or(0);
                }
                state
            })
            .collect();
        let exhausted = continuation.previous_page_exhausted
            && queue.is_empty()
            && continuation.pending_edges.is_empty();
        let unresolved_bound = continuation
            .omissions
            .iter()
            .any(|omission| omission.cause == OmissionCause::BoundsExhausted);
        Self {
            bounds: bounds.clone(),
            page_limits,
            dispositions: dispositions.clone(),
            adjacency,
            admitted,
            expanded: continuation.expanded_refs.iter().cloned().collect(),
            frontier: continuation.frontier.iter().cloned().collect(),
            omissions: continuation.omissions.clone(),
            queue,
            pending_edges: continuation.pending_edges.clone(),
            examined_edges: continuation.examined_edges.clone(),
            edges_examined: continuation.edges_examined,
            work_spent: continuation.work_spent,
            page_edges_examined: 0,
            page_work_spent: 0,
            exhausted,
            unresolved_bound,
            request_id: binding.request_id,
            reason: binding.reason,
            completeness: binding.completeness,
            request_digest: binding.request_digest,
            graph_snapshot_digest: binding.graph_snapshot_digest,
            bounds_digest: binding.bounds_digest,
        }
    }

    fn make_node_state(&self, node_ref: &str, depth: u64) -> PendingNodeState {
        let edges = self
            .adjacency
            .get(node_ref)
            .map(|edges| {
                edges
                    .iter()
                    .map(|edge| BoundedRevocationPendingEdge {
                        source_ref: edge.source_ref.clone(),
                        dependent_ref: edge.dependent_ref.clone(),
                        source_depth: depth,
                        disposition: edge.disposition,
                    })
                    .collect()
            })
            .unwrap_or_default();
        PendingNodeState {
            node_ref: node_ref.to_owned(),
            depth,
            edges,
            next_edge: 0,
        }
    }

    fn edge_budget_state(
        &self,
        edge: &BoundedRevocationPendingEdge,
    ) -> Result<EdgeBudgetState, InfluenceError> {
        let key = (edge.source_ref.clone(), edge.dependent_ref.clone());
        let Some(disposition) = self.dispositions.get(&key).copied() else {
            return Err(InfluenceError::ContinuationBindingMismatch);
        };
        if disposition != edge.disposition {
            return Err(InfluenceError::ContinuationBindingMismatch);
        }
        let requires_admission = disposition == InfluenceEdgeDisposition::PermittedCurrent
            && !self.admitted.contains_key(&edge.dependent_ref);
        let admission_depth = if requires_admission {
            edge.source_depth.checked_add(1)
        } else {
            Some(0)
        };
        let admitted_len = u64::try_from(self.admitted.len()).unwrap_or(u64::MAX);
        let global_exhausted = self
            .edges_examined
            .checked_add(1)
            .is_none_or(|next| next > self.bounds.max_edges)
            || self
                .work_spent
                .checked_add(1 + u64::from(requires_admission))
                .is_none_or(|next| next > self.bounds.max_work)
            || admission_depth.is_none_or(|depth| depth > self.bounds.max_depth)
            || (requires_admission
                && (admitted_len >= self.bounds.max_nodes
                    || admitted_len >= self.bounds.max_result));
        if global_exhausted {
            return Ok(EdgeBudgetState::GlobalExhausted);
        }
        let page_exhausted = self
            .page_edges_examined
            .checked_add(1)
            .is_none_or(|next| next > self.page_limits.max_page_edges)
            || self
                .page_work_spent
                .checked_add(1 + u64::from(requires_admission))
                .is_none_or(|next| next > self.page_limits.max_page_work);
        if page_exhausted {
            Ok(EdgeBudgetState::PageExhausted)
        } else {
            Ok(EdgeBudgetState::Fits)
        }
    }

    fn record_bound_exhaustion(&mut self, edge: &BoundedRevocationPendingEdge) {
        self.exhausted = true;
        self.unresolved_bound = true;
        self.omissions.push(RevocationOmission {
            edge_source: edge.source_ref.clone(),
            edge_dependent: edge.dependent_ref.clone(),
            cause: OmissionCause::BoundsExhausted,
        });
        self.frontier.insert(edge.dependent_ref.clone());
    }

    fn process_edge(
        &mut self,
        edge: &BoundedRevocationPendingEdge,
    ) -> Result<bool, InfluenceError> {
        let key = (edge.source_ref.clone(), edge.dependent_ref.clone());
        let Some(disposition) = self.dispositions.get(&key).copied() else {
            return Err(InfluenceError::ContinuationBindingMismatch);
        };
        if disposition != edge.disposition {
            return Err(InfluenceError::ContinuationBindingMismatch);
        }
        if let Some(cause) = omission_cause_for(disposition) {
            self.omissions.push(RevocationOmission {
                edge_source: edge.source_ref.clone(),
                edge_dependent: edge.dependent_ref.clone(),
                cause,
            });
            return Ok(false);
        }
        // `admitted` is the operation-global visited set.  It includes every
        // node discovered on this page and every node restored from a prior
        // page, so cycles, self-edges, and convergent paths terminate.
        if self.admitted.contains_key(&edge.dependent_ref) {
            return Ok(false);
        }
        let Some(child_depth) = edge.source_depth.checked_add(1) else {
            self.record_bound_exhaustion(edge);
            return Ok(true);
        };
        if child_depth > self.bounds.max_depth {
            self.record_bound_exhaustion(edge);
            return Ok(true);
        }
        let admitted_len = u64::try_from(self.admitted.len()).unwrap_or(u64::MAX);
        if admitted_len >= self.bounds.max_nodes || admitted_len >= self.bounds.max_result {
            self.record_bound_exhaustion(edge);
            return Ok(true);
        }
        // The edge examination above consumed one operation-global work unit.
        // Admission is a second independent work unit and may not borrow
        // budget from the next page.
        if self.work_spent >= self.bounds.max_work
            || self.page_work_spent >= self.page_limits.max_page_work
        {
            self.record_bound_exhaustion(edge);
            return Ok(true);
        }
        self.work_spent += 1;
        self.page_work_spent += 1;
        self.admitted
            .insert(edge.dependent_ref.clone(), child_depth);
        let child = self.make_node_state(&edge.dependent_ref, child_depth);
        self.queue.push_back(child);
        Ok(false)
    }

    fn capture_pending(&mut self) {
        let states: Vec<(String, usize, Vec<BoundedRevocationPendingEdge>)> = self
            .queue
            .iter()
            .map(|state| (state.node_ref.clone(), state.next_edge, state.edges.clone()))
            .collect();
        let mut pending_edges = Vec::new();
        for (node_ref, next_edge, edges) in states {
            self.frontier.insert(node_ref);
            for edge in edges.iter().skip(next_edge) {
                self.frontier.insert(edge.dependent_ref.clone());
                pending_edges.push(edge.clone());
            }
        }
        pending_edges.sort_by(|left, right| {
            (
                left.source_ref.as_str(),
                left.dependent_ref.as_str(),
                left.source_depth,
            )
                .cmp(&(
                    right.source_ref.as_str(),
                    right.dependent_ref.as_str(),
                    right.source_depth,
                ))
        });
        self.pending_edges = pending_edges;
    }

    fn run(&mut self) -> Result<(), InfluenceError> {
        if !self.exhausted {
            self.pending_edges.clear();
            // Frontier is current unresolved work, not an historical trace.
            // Rebuild it only if this page stops; a successful resume must end
            // with no stale page frontier.
            self.frontier.clear();
        }
        while let Some(mut entry) = self.queue.pop_front() {
            if self.exhausted {
                self.queue.push_front(entry);
                self.capture_pending();
                break;
            }
            if self.expanded.contains(&entry.node_ref) {
                continue;
            }
            let mut stopped = false;
            while entry.next_edge < entry.edges.len() {
                let edge = entry.edges[entry.next_edge].clone();
                match self.edge_budget_state(&edge)? {
                    EdgeBudgetState::Fits => {}
                    EdgeBudgetState::GlobalExhausted => {
                        self.record_bound_exhaustion(&edge);
                        stopped = true;
                        break;
                    }
                    EdgeBudgetState::PageExhausted => {
                        self.exhausted = true;
                        stopped = true;
                        break;
                    }
                }
                self.work_spent += 1;
                self.page_work_spent += 1;
                self.edges_examined += 1;
                self.page_edges_examined += 1;
                entry.next_edge += 1;
                self.examined_edges.push(edge.clone());
                if self.process_edge(&edge)? {
                    stopped = true;
                    break;
                }
            }
            if stopped {
                // If the last edge caused the stop, this node has no
                // unexpanded edge position even though the operation remains
                // incomplete.  Otherwise retain the complete source-bound
                // suffix and the rest of the queue.
                if entry.next_edge == entry.edges.len() {
                    self.expanded.insert(entry.node_ref);
                } else {
                    self.queue.push_front(entry);
                }
                self.capture_pending();
                break;
            }
            self.expanded.insert(entry.node_ref);
        }
        Ok(())
    }

    fn canonicalize_vectors(&mut self, pending: &mut [BoundedRevocationPendingNode]) {
        pending.sort_by(|left, right| {
            (left.node_ref.as_str(), left.depth).cmp(&(right.node_ref.as_str(), right.depth))
        });
        self.pending_edges.sort_by(|left, right| {
            (
                left.source_ref.as_str(),
                left.dependent_ref.as_str(),
                left.source_depth,
            )
                .cmp(&(
                    right.source_ref.as_str(),
                    right.dependent_ref.as_str(),
                    right.source_depth,
                ))
        });
        self.omissions.sort_by(|left, right| {
            (
                left.edge_source.as_str(),
                left.edge_dependent.as_str(),
                omission_cause_rank(left.cause),
            )
                .cmp(&(
                    right.edge_source.as_str(),
                    right.edge_dependent.as_str(),
                    omission_cause_rank(right.cause),
                ))
        });
        self.omissions.dedup();
        self.examined_edges.sort_by(|left, right| {
            (
                left.source_ref.as_str(),
                left.dependent_ref.as_str(),
                left.source_depth,
            )
                .cmp(&(
                    right.source_ref.as_str(),
                    right.dependent_ref.as_str(),
                    right.source_depth,
                ))
        });
    }

    fn finish(
        mut self,
        request: &BoundedRevocationRequest,
    ) -> Result<BoundedRevocationOutcome, InfluenceError> {
        let mut pending: Vec<BoundedRevocationPendingNode> = self
            .queue
            .iter()
            .map(|entry| BoundedRevocationPendingNode {
                node_ref: entry.node_ref.clone(),
                depth: entry.depth,
            })
            .collect();
        self.canonicalize_vectors(&mut pending);
        let admitted_nodes: Vec<BoundedRevocationPendingNode> = self
            .admitted
            .iter()
            .map(|(node_ref, depth)| BoundedRevocationPendingNode {
                node_ref: node_ref.clone(),
                depth: *depth,
            })
            .collect();
        let affected_refs: Vec<String> = admitted_nodes
            .iter()
            .map(|node| node.node_ref.clone())
            .collect();
        let expanded_refs: Vec<String> = self.expanded.iter().cloned().collect();
        let frontier: Vec<String> = self.frontier.iter().cloned().collect();
        let has_pending = !self.queue.is_empty() || !self.pending_edges.is_empty();
        let complete = !self.exhausted && !has_pending && !self.unresolved_bound;
        let continuation = if self.exhausted || has_pending || self.unresolved_bound {
            let mut continuation = BoundedRevocationContinuation {
                schema_version: BOUNDED_REVOCATION_CONTINUATION_SCHEMA.to_owned(),
                request_id: self.request_id,
                root_ref: request.root_ref.clone(),
                reason: self.reason,
                completeness: self.completeness,
                request_digest: self.request_digest,
                graph_snapshot_digest: self.graph_snapshot_digest,
                state_fence: request.state_fence.clone(),
                bounds_digest: self.bounds_digest,
                admitted_refs: affected_refs.clone(),
                admitted_nodes,
                expanded_refs: expanded_refs.clone(),
                pending,
                pending_edges: self.pending_edges.clone(),
                examined_edges: self.examined_edges.clone(),
                edges_examined: self.edges_examined,
                work_spent: self.work_spent,
                omissions: self.omissions.clone(),
                frontier: frontier.clone(),
                previous_page_exhausted: self.exhausted || self.unresolved_bound,
                continuation_digest: String::new(),
            };
            continuation.continuation_digest = continuation.digest()?;
            Some(continuation)
        } else {
            None
        };
        let continuation_token =
            continuation
                .as_ref()
                .map(|continuation| BoundedRevocationContinuationToken {
                    digest: continuation.continuation_digest.clone(),
                });
        Ok(BoundedRevocationOutcome {
            root_ref: request.root_ref.clone(),
            affected_refs,
            frontier,
            omissions: self.omissions,
            work_spent: self.work_spent,
            complete,
            continuation,
            continuation_token,
        })
    }
}

fn check_bounded_header(
    request: &BoundedRevocationRequest,
    bounds: &RevocationBounds,
) -> Result<(), InfluenceError> {
    text(&request.request_id, "request_id")?;
    text(&request.root_ref, "root_ref")?;
    request
        .state_fence
        .validate()
        .map_err(|_| InfluenceError::InvalidField("state_fence"))?;
    bounds.validate()?;
    if matches!(request.completeness, ClosureCompleteness::Partial) {
        return Err(InfluenceError::UnknownCompleteness);
    }
    if !request.resumed_visited.is_empty() {
        return Err(InfluenceError::LegacyResumedVisited);
    }
    Ok(())
}

fn dedup_qualified_edges(
    request: &BoundedRevocationRequest,
) -> Result<BTreeMap<(String, String), InfluenceEdgeDisposition>, InfluenceError> {
    let mut dispositions: BTreeMap<(String, String), InfluenceEdgeDisposition> = BTreeMap::new();
    for edge in &request.edges {
        text(&edge.source_ref, "edge.source_ref")?;
        text(&edge.dependent_ref, "edge.dependent_ref")?;
        let key = (edge.source_ref.clone(), edge.dependent_ref.clone());
        if let Some(existing) = dispositions.get(&key) {
            if *existing != edge.disposition {
                return Err(InfluenceError::DuplicateEdge);
            }
        } else {
            dispositions.insert(key, edge.disposition);
        }
    }
    Ok(dispositions)
}

fn continuation_strings(
    values: &[String],
    field: &'static str,
) -> Result<BTreeSet<String>, InfluenceError> {
    let mut result = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for value in values {
        text(value, field)?;
        if previous.is_some_and(|prior| prior > value.as_str()) {
            return Err(InfluenceError::InvalidContinuation);
        }
        if !result.insert(value.clone()) {
            return Err(InfluenceError::DuplicateReference(field));
        }
        previous = Some(value.as_str());
    }
    Ok(result)
}

fn continuation_nodes(
    values: &[BoundedRevocationPendingNode],
    field: &'static str,
) -> Result<BTreeMap<String, u64>, InfluenceError> {
    let mut result = BTreeMap::new();
    for value in values {
        text(&value.node_ref, field)?;
        if result.insert(value.node_ref.clone(), value.depth).is_some() {
            return Err(InfluenceError::DuplicateReference(field));
        }
    }
    Ok(result)
}

fn continuation_pending_nodes(
    values: &[BoundedRevocationPendingNode],
) -> Result<BTreeMap<String, u64>, InfluenceError> {
    let result = continuation_nodes(values, "continuation.pending")?;
    let mut previous: Option<(&str, u64)> = None;
    for value in values {
        let key = (value.node_ref.as_str(), value.depth);
        if previous.is_some_and(|prior| prior >= key) {
            return Err(InfluenceError::InvalidContinuation);
        }
        previous = Some(key);
    }
    Ok(result)
}

fn continuation_edges(
    values: &[BoundedRevocationPendingEdge],
    field: &'static str,
) -> Result<Vec<BoundedRevocationPendingEdge>, InfluenceError> {
    let mut result = Vec::with_capacity(values.len());
    let mut previous: Option<(&str, &str, u64)> = None;
    for value in values {
        text(&value.source_ref, field)?;
        text(&value.dependent_ref, field)?;
        let key = (
            value.source_ref.as_str(),
            value.dependent_ref.as_str(),
            value.source_depth,
        );
        if previous.is_some_and(|prior| prior >= key) {
            return Err(InfluenceError::InvalidContinuation);
        }
        result.push(value.clone());
        previous = Some(key);
    }
    Ok(result)
}

fn validate_omissions(
    values: &[RevocationOmission],
) -> Result<BTreeMap<(String, String), OmissionCause>, InfluenceError> {
    let mut result = BTreeMap::new();
    let mut previous: Option<(&str, &str, u8)> = None;
    for value in values {
        text(&value.edge_source, "continuation.omissions.edge_source")?;
        text(
            &value.edge_dependent,
            "continuation.omissions.edge_dependent",
        )?;
        let key = (
            value.edge_source.as_str(),
            value.edge_dependent.as_str(),
            omission_cause_rank(value.cause),
        );
        if previous.is_some_and(|prior| prior >= key) {
            return Err(InfluenceError::InvalidContinuation);
        }
        if result
            .insert(
                (value.edge_source.clone(), value.edge_dependent.clone()),
                value.cause,
            )
            .is_some()
        {
            return Err(InfluenceError::InvalidContinuation);
        }
        previous = Some(key);
    }
    Ok(result)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

struct ValidatedContinuationState {
    admitted_nodes: BTreeMap<String, u64>,
    expanded_refs: BTreeSet<String>,
    pending: BTreeMap<String, u64>,
    pending_edges: Vec<BoundedRevocationPendingEdge>,
    examined_edges: Vec<BoundedRevocationPendingEdge>,
    omission_map: BTreeMap<(String, String), OmissionCause>,
    frontier: BTreeSet<String>,
}

fn validate_continuation_binding(
    request: &BoundedRevocationRequest,
    binding: &BoundedBinding,
    continuation: &BoundedRevocationContinuation,
    token: &BoundedRevocationContinuationToken,
) -> Result<(), InfluenceError> {
    if continuation.schema_version != BOUNDED_REVOCATION_CONTINUATION_SCHEMA {
        return Err(InfluenceError::UnsupportedContinuation);
    }
    if continuation.request_id != request.request_id
        || continuation.root_ref != request.root_ref
        || continuation.reason != request.reason
        || continuation.completeness != request.completeness
        || continuation.request_digest != binding.request_digest
        || continuation.graph_snapshot_digest != binding.graph_snapshot_digest
        || continuation.bounds_digest != binding.bounds_digest
        || continuation.state_fence != request.state_fence
    {
        return Err(InfluenceError::ContinuationBindingMismatch);
    }
    if !is_sha256_hex(&continuation.request_digest)
        || !is_sha256_hex(&continuation.graph_snapshot_digest)
        || !is_sha256_hex(&continuation.bounds_digest)
        || !is_sha256_hex(&continuation.continuation_digest)
        || continuation.continuation_digest != continuation.digest()?
        || token.digest() != continuation.continuation_digest
    {
        return Err(InfluenceError::InvalidContinuation);
    }
    if !continuation.previous_page_exhausted
        || !matches!(continuation.completeness, ClosureCompleteness::Complete)
    {
        return Err(InfluenceError::InvalidContinuation);
    }
    Ok(())
}

fn validate_continuation_counters(
    bounds: &RevocationBounds,
    continuation: &BoundedRevocationContinuation,
    admitted_len: u64,
    examined_len: u64,
) -> Result<(), InfluenceError> {
    if continuation.edges_examined > bounds.max_edges
        || continuation.work_spent > bounds.max_work
        || admitted_len > bounds.max_nodes
        || admitted_len > bounds.max_result
        || continuation.edges_examined != examined_len
    {
        return Err(InfluenceError::InvalidContinuation);
    }
    let expected_work = continuation
        .edges_examined
        .checked_add(admitted_len)
        .ok_or(InfluenceError::InvalidContinuation)?;
    if continuation.work_spent != expected_work {
        return Err(InfluenceError::InvalidContinuation);
    }
    Ok(())
}

fn validate_continuation_state(
    request: &BoundedRevocationRequest,
    bounds: &RevocationBounds,
    continuation: &BoundedRevocationContinuation,
) -> Result<ValidatedContinuationState, InfluenceError> {
    let admitted_refs =
        continuation_strings(&continuation.admitted_refs, "continuation.admitted_refs")?;
    let admitted_nodes =
        continuation_nodes(&continuation.admitted_nodes, "continuation.admitted_nodes")?;
    let expanded_refs =
        continuation_strings(&continuation.expanded_refs, "continuation.expanded_refs")?;
    let pending = continuation_pending_nodes(&continuation.pending)?;
    let pending_edges =
        continuation_edges(&continuation.pending_edges, "continuation.pending_edges")?;
    let examined_edges =
        continuation_edges(&continuation.examined_edges, "continuation.examined_edges")?;
    let omission_map = validate_omissions(&continuation.omissions)?;
    let frontier = continuation_strings(&continuation.frontier, "continuation.frontier")?;

    if continuation.pending.is_empty()
        && continuation.pending_edges.is_empty()
        && !omission_map
            .values()
            .any(|cause| *cause == OmissionCause::BoundsExhausted)
    {
        return Err(InfluenceError::InvalidContinuation);
    }
    if admitted_nodes.is_empty()
        || admitted_refs.len() != admitted_nodes.len()
        || admitted_nodes
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != continuation
                .admitted_refs
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
    {
        return Err(InfluenceError::InvalidContinuation);
    }
    if admitted_nodes.get(&request.root_ref) != Some(&0) {
        return Err(InfluenceError::ContinuationBindingMismatch);
    }
    if expanded_refs
        .iter()
        .any(|node_ref| !admitted_nodes.contains_key(node_ref))
        || pending
            .iter()
            .any(|(node_ref, _)| !admitted_nodes.contains_key(node_ref))
        || expanded_refs
            .iter()
            .any(|node_ref| pending.contains_key(node_ref))
    {
        return Err(InfluenceError::InvalidContinuation);
    }
    for (node_ref, depth) in &admitted_nodes {
        if *depth > bounds.max_depth
            || (!expanded_refs.contains(node_ref) && !pending.contains_key(node_ref))
        {
            return Err(InfluenceError::InvalidContinuation);
        }
    }
    let admitted_len = u64::try_from(admitted_nodes.len()).unwrap_or(u64::MAX);
    let examined_len = u64::try_from(examined_edges.len()).unwrap_or(u64::MAX);
    validate_continuation_counters(bounds, continuation, admitted_len, examined_len)?;

    Ok(ValidatedContinuationState {
        admitted_nodes,
        expanded_refs,
        pending,
        pending_edges,
        examined_edges,
        omission_map,
        frontier,
    })
}

fn validate_continuation_edge_binding(
    edge: &BoundedRevocationPendingEdge,
    source_depth: u64,
    dispositions: &BTreeMap<(String, String), InfluenceEdgeDisposition>,
) -> Result<(), InfluenceError> {
    if edge.source_depth != source_depth {
        return Err(InfluenceError::InvalidContinuation);
    }
    let disposition = dispositions
        .get(&(edge.source_ref.clone(), edge.dependent_ref.clone()))
        .ok_or(InfluenceError::ContinuationBindingMismatch)?;
    if *disposition != edge.disposition {
        return Err(InfluenceError::ContinuationBindingMismatch);
    }
    Ok(())
}

struct ContinuationEdgeIndexes {
    examined_by_key: BTreeMap<(String, String), BoundedRevocationPendingEdge>,
    pending_by_source: BTreeMap<String, BTreeSet<String>>,
}

fn index_continuation_edges(
    state: &ValidatedContinuationState,
    dispositions: &BTreeMap<(String, String), InfluenceEdgeDisposition>,
) -> Result<ContinuationEdgeIndexes, InfluenceError> {
    let mut examined_by_key = BTreeMap::new();
    for edge in &state.examined_edges {
        let source_depth = state
            .admitted_nodes
            .get(&edge.source_ref)
            .ok_or(InfluenceError::InvalidContinuation)?;
        validate_continuation_edge_binding(edge, *source_depth, dispositions)?;
        let key = (edge.source_ref.clone(), edge.dependent_ref.clone());
        if examined_by_key.insert(key, edge.clone()).is_some() {
            return Err(InfluenceError::InvalidContinuation);
        }
    }

    let mut pending_by_source: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for edge in &state.pending_edges {
        let source_depth = state
            .pending
            .get(&edge.source_ref)
            .ok_or(InfluenceError::InvalidContinuation)?;
        validate_continuation_edge_binding(edge, *source_depth, dispositions)?;
        let key = (edge.source_ref.clone(), edge.dependent_ref.clone());
        if examined_by_key.contains_key(&key) {
            return Err(InfluenceError::InvalidContinuation);
        }
        pending_by_source
            .entry(edge.source_ref.clone())
            .or_default()
            .insert(edge.dependent_ref.clone());
    }
    Ok(ContinuationEdgeIndexes {
        examined_by_key,
        pending_by_source,
    })
}

fn validate_adjacency_partition(
    state: &ValidatedContinuationState,
    dispositions: &BTreeMap<(String, String), InfluenceEdgeDisposition>,
    examined_by_key: &BTreeMap<(String, String), BoundedRevocationPendingEdge>,
    pending_by_source: &BTreeMap<String, BTreeSet<String>>,
) -> Result<(), InfluenceError> {
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (source_ref, dependent_ref) in dispositions.keys() {
        adjacency
            .entry(source_ref.clone())
            .or_default()
            .push(dependent_ref.clone());
    }
    for targets in adjacency.values_mut() {
        targets.sort();
    }
    for (source_ref, targets) in adjacency {
        if !state.admitted_nodes.contains_key(&source_ref) {
            if examined_by_key
                .keys()
                .any(|(examined_source, _)| examined_source == &source_ref)
                || pending_by_source.contains_key(&source_ref)
            {
                return Err(InfluenceError::InvalidContinuation);
            }
            continue;
        }
        let expected_pending: Vec<String> = targets
            .iter()
            .filter(|dependent_ref| {
                !examined_by_key.contains_key(&(source_ref.clone(), (*dependent_ref).clone()))
            })
            .cloned()
            .collect();
        let actual_pending = pending_by_source
            .get(&source_ref)
            .map(|targets| targets.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        if actual_pending != expected_pending
            || (state.expanded_refs.contains(&source_ref) && !expected_pending.is_empty())
            || (state.pending.contains_key(&source_ref)
                && !targets.is_empty()
                && expected_pending.is_empty())
        {
            return Err(InfluenceError::InvalidContinuation);
        }
        for dependent_ref in &targets {
            if !examined_by_key.contains_key(&(source_ref.clone(), dependent_ref.clone()))
                && !pending_by_source
                    .get(&source_ref)
                    .is_some_and(|values| values.contains(dependent_ref))
            {
                return Err(InfluenceError::InvalidContinuation);
            }
        }
    }
    Ok(())
}

fn validate_examined_edge_omissions(
    state: &ValidatedContinuationState,
    dispositions: &BTreeMap<(String, String), InfluenceEdgeDisposition>,
) -> Result<(), InfluenceError> {
    for edge in &state.examined_edges {
        let key = (edge.source_ref.clone(), edge.dependent_ref.clone());
        let disposition = dispositions
            .get(&key)
            .copied()
            .ok_or(InfluenceError::ContinuationBindingMismatch)?;
        let target_admitted = state.admitted_nodes.contains_key(&edge.dependent_ref);
        match disposition {
            InfluenceEdgeDisposition::PermittedCurrent => {
                if (!target_admitted
                    && state.omission_map.get(&key) != Some(&OmissionCause::BoundsExhausted))
                    || (target_admitted && state.omission_map.contains_key(&key))
                {
                    return Err(InfluenceError::InvalidContinuation);
                }
            }
            blocked => {
                if omission_cause_for(blocked) != state.omission_map.get(&key).copied() {
                    return Err(InfluenceError::InvalidContinuation);
                }
            }
        }
    }
    Ok(())
}

fn validate_recorded_omissions(
    state: &ValidatedContinuationState,
    dispositions: &BTreeMap<(String, String), InfluenceEdgeDisposition>,
    examined_by_key: &BTreeMap<(String, String), BoundedRevocationPendingEdge>,
) -> Result<(), InfluenceError> {
    for ((source_ref, dependent_ref), cause) in &state.omission_map {
        let key = (source_ref.clone(), dependent_ref.clone());
        let disposition = dispositions
            .get(&key)
            .copied()
            .ok_or(InfluenceError::ContinuationBindingMismatch)?;
        let examined = examined_by_key.get(&key);
        let pending = state.pending_edges.iter().find(|edge| {
            edge.source_ref.as_str() == source_ref.as_str()
                && edge.dependent_ref.as_str() == dependent_ref.as_str()
        });
        if *cause == OmissionCause::BoundsExhausted {
            if disposition != InfluenceEdgeDisposition::PermittedCurrent
                || examined.is_some_and(|edge| edge.disposition != disposition)
                || pending.is_some_and(|edge| edge.disposition != disposition)
                || (examined.is_none() && pending.is_none())
            {
                return Err(InfluenceError::InvalidContinuation);
            }
        } else {
            let Some(edge) = examined else {
                return Err(InfluenceError::InvalidContinuation);
            };
            if edge.disposition != disposition || omission_cause_for(disposition) != Some(*cause) {
                return Err(InfluenceError::InvalidContinuation);
            }
        }
    }
    Ok(())
}

fn validate_reachability_and_frontier(
    request: &BoundedRevocationRequest,
    state: &ValidatedContinuationState,
) -> Result<(), InfluenceError> {
    for (node_ref, depth) in &state.admitted_nodes {
        if node_ref == &request.root_ref {
            continue;
        }
        let reachable = state.examined_edges.iter().any(|edge| {
            edge.dependent_ref == *node_ref
                && edge.disposition == InfluenceEdgeDisposition::PermittedCurrent
                && edge
                    .source_depth
                    .checked_add(1)
                    .is_some_and(|child_depth| child_depth == *depth)
        });
        if !reachable {
            return Err(InfluenceError::InvalidContinuation);
        }
    }
    let mut expected_frontier: BTreeSet<String> = state.pending.keys().cloned().collect();
    expected_frontier.extend(
        state
            .pending_edges
            .iter()
            .map(|edge| edge.dependent_ref.clone()),
    );
    expected_frontier.extend(
        state
            .omission_map
            .iter()
            .filter(|(_, cause)| **cause == OmissionCause::BoundsExhausted)
            .map(|((_, dependent_ref), _)| dependent_ref.clone()),
    );
    if state.frontier != expected_frontier {
        return Err(InfluenceError::InvalidContinuation);
    }
    Ok(())
}

fn validate_continuation(
    request: &BoundedRevocationRequest,
    bounds: &RevocationBounds,
    dispositions: &BTreeMap<(String, String), InfluenceEdgeDisposition>,
    binding: &BoundedBinding,
    continuation: &BoundedRevocationContinuation,
    token: &BoundedRevocationContinuationToken,
) -> Result<(), InfluenceError> {
    validate_continuation_binding(request, binding, continuation, token)?;
    let state = validate_continuation_state(request, bounds, continuation)?;
    let indexes = index_continuation_edges(&state, dispositions)?;
    validate_adjacency_partition(
        &state,
        dispositions,
        &indexes.examined_by_key,
        &indexes.pending_by_source,
    )?;
    validate_examined_edge_omissions(&state, dispositions)?;
    validate_recorded_omissions(&state, dispositions, &indexes.examined_by_key)?;
    validate_reachability_and_frontier(request, &state)
}

/// Bounded transitive revocation over an explicit qualified edge set.
///
/// Validates the request, fence, and bounds; rejects a `PARTIAL` denominator;
/// deduplicates identical edges while rejecting conflicting dispositions for
/// the same pair; then traverses `PERMITTED_CURRENT` source-to-dependent edges
/// breadth-first in deterministic order under the supplied limits.
///
/// A nonempty legacy `resumed_visited` is intentionally rejected.  Use
/// [`resume_bounded_revocation`] with the exact continuation returned by a
/// prior exhausted page; a visited-only list cannot describe unexpanded edge
/// positions and therefore cannot create authority.
pub fn revoke_bounded(
    request: &BoundedRevocationRequest,
    bounds: &RevocationBounds,
) -> Result<BoundedRevocationOutcome, InfluenceError> {
    revoke_bounded_page(
        request,
        bounds,
        BoundedRevocationPageLimits::all_global_work(bounds),
    )
}

/// Start one explicitly page-limited traversal without weakening the
/// operation-global bounds. Use the returned continuation with
/// [`resume_bounded_revocation`] until it proves completion or a global bound
/// remains exhausted.
pub fn revoke_bounded_page(
    request: &BoundedRevocationRequest,
    bounds: &RevocationBounds,
    page_limits: BoundedRevocationPageLimits,
) -> Result<BoundedRevocationOutcome, InfluenceError> {
    check_bounded_header(request, bounds)?;
    page_limits.validate()?;
    let dispositions = dedup_qualified_edges(request)?;
    let binding = bounded_binding(request, bounds)?;
    let mut traversal = BoundedTraversal::new(request, bounds, page_limits, &dispositions, binding);
    traversal.run()?;
    traversal.finish(request)
}

/// Resume one source-bound bounded revocation operation.
///
/// The request, graph snapshot, fence, global bounds, admitted/expanded
/// closure, and cumulative counters are validated before the saved queue can
/// run. `page_limits` applies only to this call and cannot raise the bound
/// global limits carried by the continuation. `continuation_token` is the
/// opaque capability returned with the preceding live outcome; a deserialized
/// or caller-recomputed digest is not sufficient. The operation is never
/// re-rooted and the root is never re-admitted.
pub fn resume_bounded_revocation(
    request: &BoundedRevocationRequest,
    continuation: &BoundedRevocationContinuation,
    continuation_token: &BoundedRevocationContinuationToken,
    bounds: &RevocationBounds,
    page_limits: BoundedRevocationPageLimits,
) -> Result<BoundedRevocationOutcome, InfluenceError> {
    check_bounded_header(request, bounds)?;
    page_limits.validate()?;
    let dispositions = dedup_qualified_edges(request)?;
    let binding = bounded_binding(request, bounds)?;
    validate_continuation(
        request,
        bounds,
        &dispositions,
        &binding,
        continuation,
        continuation_token,
    )?;
    let mut traversal = BoundedTraversal::from_continuation(
        bounds,
        page_limits,
        &dispositions,
        binding,
        continuation,
    );
    traversal.run()?;
    traversal.finish(request)
}

// ---------------------------------------------------------------------------
// Issue 1904: reachable influence runtime path.
//
// Allowed influence must flow through one reachable staged path:
//
//   context-admission -> pending-injection -> material-decision -> result-binding
//
// Every stage calls the same mandatory policy gate (`policy_gate`) and carries
// a digest-bound receipt from the previous stage, so no stage is reachable by
// skipping its predecessor. The gate returns an allow / deny / degraded-use
// verdict with explicit reasons. Retrieval (`retrieve_view`) takes only a
// shared reference and never mutates support or influence.
// ---------------------------------------------------------------------------

/// Wire/schema revision of the staged influence runtime path.
pub const RUNTIME_PATH_VERSION: &str = "eliot-influence-runtime-v1";

/// Requested runtime use on the reachable influence path.
///
/// Each use maps to the minimum [`EpistemicUse`] that must be present in the
/// subject's allowed set: exploratory reads need `OBSERVATION`, material
/// decision input and confirmatory acceptance need `CANDIDATE_EVIDENCE`, and
/// verifier input needs `VERIFICATION_INPUT`. Confirmatory acceptance
/// additionally requires an explicit qualifying transition
/// (`qualified_for_confirmatory`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeUse {
    ExploratoryRead,
    DecisionInput,
    VerifierInput,
    ConfirmatoryAcceptance,
}

impl RuntimeUse {
    fn required_use(self) -> EpistemicUse {
        match self {
            Self::ExploratoryRead => EpistemicUse::Observation,
            Self::DecisionInput | Self::ConfirmatoryAcceptance => EpistemicUse::CandidateEvidence,
            Self::VerifierInput => EpistemicUse::VerificationInput,
        }
    }

    fn rank(use_: EpistemicUse) -> u8 {
        match use_ {
            EpistemicUse::Observation => 0,
            EpistemicUse::AttributedInput => 1,
            EpistemicUse::CandidateEvidence => 2,
            EpistemicUse::VerificationInput => 3,
        }
    }
}

/// Boundary stage of the reachable path. Receipt order enforces reachability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeStage {
    ContextAdmission,
    PendingInjection,
    MaterialDecision,
    ResultBinding,
}

/// Allow / deny / degraded-use outcome of the mandatory policy gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeVerdictKind {
    Allow,
    DegradedUse,
    Deny,
}

/// Explicit reason carried by a runtime verdict. Deny and degraded-use
/// verdicts always carry at least one reason naming the missing allowance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeReason {
    RecordNotRetrievable,
    InfluenceNotActive {
        state: InfluenceState,
    },
    EpistemicUseNotAllowed {
        requested: EpistemicUse,
        allowed: Vec<EpistemicUse>,
    },
    ExploratoryOnlyCannotSatisfyVerifier,
    ExploratoryOnlyCannotSatisfyConfirmatory,
    VerifierRequiresVerificationInput,
    ConfirmatoryRequiresQualification,
    UseCappedToExploratory,
}

/// Subject gated by the runtime path.
///
/// `support_revision` names the support state and `influence` names the
/// influence state; neither is mutated by retrieval. A qualifying transition
/// produces a new subject value and leaves the original untouched.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSubject {
    pub subject_ref: String,
    pub origin_ref: String,
    pub allowed_uses: Vec<EpistemicUse>,
    pub influence: InfluenceState,
    pub retrievable: bool,
    pub qualified_for_confirmatory: bool,
    pub support_revision: u64,
    pub state_fence: StateFence,
}

impl RuntimeSubject {
    /// Build a subject, rejecting blank references and an empty use set.
    ///
    /// New subjects start unqualified for confirmatory acceptance; only an
    /// explicit [`qualify_transition`] can set the qualification flag.
    pub fn new(
        subject_ref: String,
        origin_ref: String,
        allowed_uses: Vec<EpistemicUse>,
        influence: InfluenceState,
        retrievable: bool,
        support_revision: u64,
        state_fence: StateFence,
    ) -> Result<Self, InfluenceRuntimeError> {
        let subject = Self {
            subject_ref,
            origin_ref,
            allowed_uses,
            influence,
            retrievable,
            qualified_for_confirmatory: false,
            support_revision,
            state_fence,
        };
        subject.validate()?;
        Ok(subject)
    }

    /// Build a subject from live contract records so allowed influence stays
    /// bound to source assurance and the dependency closure.
    pub fn from_contracts(
        subject_ref: String,
        provenance: &ProvenanceRecord,
        closure: &InfluenceDependencyClosure,
        retrievable: bool,
        support_revision: u64,
    ) -> Result<Self, InfluenceRuntimeError> {
        provenance
            .validate()
            .map_err(|_| InfluenceRuntimeError::InvalidField("provenance"))?;
        closure
            .validate()
            .map_err(|_| InfluenceRuntimeError::InvalidField("dependency_closure"))?;
        Self::new(
            subject_ref,
            provenance.origin_ref.clone(),
            provenance.source_assurance.allowed_epistemic_use.clone(),
            closure.current_influence,
            retrievable,
            support_revision,
            provenance.state_fence.clone(),
        )
    }

    pub fn validate(&self) -> Result<(), InfluenceRuntimeError> {
        if self.subject_ref.trim().is_empty() || self.subject_ref.chars().any(char::is_control) {
            return Err(InfluenceRuntimeError::InvalidField("subject_ref"));
        }
        if self.origin_ref.trim().is_empty() || self.origin_ref.chars().any(char::is_control) {
            return Err(InfluenceRuntimeError::InvalidField("origin_ref"));
        }
        if self.allowed_uses.is_empty() {
            return Err(InfluenceRuntimeError::InvalidField("allowed_uses"));
        }
        self.state_fence
            .validate()
            .map_err(|_| InfluenceRuntimeError::InvalidField("state_fence"))?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String, InfluenceRuntimeError> {
        self.validate()?;
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceRuntimeError::Canonicalization)
    }

    fn max_rank(&self) -> u8 {
        self.allowed_uses
            .iter()
            .copied()
            .map(RuntimeUse::rank)
            .max()
            .unwrap_or(0)
    }

    fn is_exploratory_only(&self) -> bool {
        self.max_rank() <= RuntimeUse::rank(EpistemicUse::Observation)
    }
}

/// Read-only retrieval view. Constructed only through [`retrieve_view`], which
/// takes a shared reference, so retrieval cannot mutate support or influence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeView {
    pub subject_ref: String,
    pub origin_ref: String,
    pub allowed_uses: Vec<EpistemicUse>,
    pub influence: InfluenceState,
    pub retrievable: bool,
    pub support_revision: u64,
}

/// Retrieve a read-only view without mutating support or influence.
///
/// Takes only `&RuntimeSubject` (no `&mut`, no interior mutability), so the
/// caller's subject value is unchanged by retrieval.
#[must_use]
pub fn retrieve_view(subject: &RuntimeSubject) -> RuntimeView {
    RuntimeView {
        subject_ref: subject.subject_ref.clone(),
        origin_ref: subject.origin_ref.clone(),
        allowed_uses: subject.allowed_uses.clone(),
        influence: subject.influence,
        retrievable: subject.retrievable,
        support_revision: subject.support_revision,
    }
}

/// Allow / deny / degraded-use verdict of the mandatory policy gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVerdict {
    pub subject_ref: String,
    pub subject_digest: String,
    pub requested: RuntimeUse,
    pub kind: RuntimeVerdictKind,
    pub reasons: Vec<RuntimeReason>,
    pub allowed_fallback: Option<RuntimeUse>,
    pub state_fence: StateFence,
}

impl RuntimeVerdict {
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self.kind, RuntimeVerdictKind::Allow)
    }
}

/// Mandatory policy gate for the reachable influence runtime path.
///
/// Every boundary (`admit_context`, `inject_pending`, `decide_material`,
/// `bind_result`) calls this gate; there is no other admission route. Allow
/// carries no reasons; deny and degraded-use always state at least one
/// reason naming the missing allowance.
pub fn policy_gate(
    subject: &RuntimeSubject,
    requested: RuntimeUse,
) -> Result<RuntimeVerdict, InfluenceRuntimeError> {
    subject.validate()?;
    let subject_digest = subject.digest()?;
    let stated =
        |kind: RuntimeVerdictKind, reasons: Vec<RuntimeReason>, fallback: Option<RuntimeUse>| {
            RuntimeVerdict {
                subject_ref: subject.subject_ref.clone(),
                subject_digest: subject_digest.clone(),
                requested,
                kind,
                reasons,
                allowed_fallback: fallback,
                state_fence: subject.state_fence.clone(),
            }
        };

    if !subject.retrievable {
        return Ok(stated(
            RuntimeVerdictKind::Deny,
            vec![RuntimeReason::RecordNotRetrievable],
            None,
        ));
    }
    if subject.influence != InfluenceState::Active {
        return Ok(stated(
            RuntimeVerdictKind::Deny,
            vec![RuntimeReason::InfluenceNotActive {
                state: subject.influence,
            }],
            None,
        ));
    }

    let required = requested.required_use();
    let max_rank = subject.max_rank();
    if max_rank >= RuntimeUse::rank(required) {
        if matches!(requested, RuntimeUse::ConfirmatoryAcceptance)
            && !subject.qualified_for_confirmatory
        {
            return Ok(stated(
                RuntimeVerdictKind::DegradedUse,
                vec![RuntimeReason::ConfirmatoryRequiresQualification],
                Some(RuntimeUse::DecisionInput),
            ));
        }
        return Ok(stated(RuntimeVerdictKind::Allow, Vec::new(), None));
    }

    let not_allowed = RuntimeReason::EpistemicUseNotAllowed {
        requested: required,
        allowed: subject.allowed_uses.clone(),
    };
    if subject.is_exploratory_only() {
        let specific = match requested {
            RuntimeUse::ExploratoryRead => None,
            RuntimeUse::DecisionInput => Some(RuntimeReason::UseCappedToExploratory),
            RuntimeUse::VerifierInput => Some(RuntimeReason::ExploratoryOnlyCannotSatisfyVerifier),
            RuntimeUse::ConfirmatoryAcceptance => {
                Some(RuntimeReason::ExploratoryOnlyCannotSatisfyConfirmatory)
            }
        };
        let mut reasons = vec![not_allowed];
        if let Some(reason) = specific {
            reasons.push(reason);
        }
        return Ok(stated(RuntimeVerdictKind::Deny, reasons, None));
    }
    let (reasons, fallback) = match requested {
        RuntimeUse::ExploratoryRead => (vec![not_allowed], None),
        RuntimeUse::DecisionInput => (
            vec![not_allowed, RuntimeReason::UseCappedToExploratory],
            Some(RuntimeUse::ExploratoryRead),
        ),
        RuntimeUse::VerifierInput => (
            vec![
                not_allowed,
                RuntimeReason::VerifierRequiresVerificationInput,
            ],
            Some(RuntimeUse::DecisionInput),
        ),
        RuntimeUse::ConfirmatoryAcceptance => (
            vec![
                not_allowed,
                RuntimeReason::ConfirmatoryRequiresQualification,
            ],
            Some(RuntimeUse::DecisionInput),
        ),
    };
    let kind = if fallback.is_some() {
        RuntimeVerdictKind::DegradedUse
    } else {
        RuntimeVerdictKind::Deny
    };
    Ok(stated(kind, reasons, fallback))
}

/// Explicit qualifying transition: evidence-backed promotion of allowed use.
///
/// Takes a shared reference and returns a new subject; the input is never
/// mutated. Adding a decision-grade use (`CANDIDATE_EVIDENCE` or stronger)
/// with a non-blank evidence reference also sets the confirmatory
/// qualification flag. Support revision and influence are carried over
/// unchanged: qualification changes what may be used, never the support or
/// influence state itself.
pub fn qualify_transition(
    subject: &RuntimeSubject,
    added: EpistemicUse,
    evidence_ref: &str,
) -> Result<RuntimeSubject, InfluenceRuntimeError> {
    subject.validate()?;
    if evidence_ref.trim().is_empty() || evidence_ref.chars().any(char::is_control) {
        return Err(InfluenceRuntimeError::InvalidField("evidence_ref"));
    }
    if subject.influence != InfluenceState::Active {
        return Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::MaterialDecision,
            subject: subject.subject_ref.clone(),
            reasons: vec![RuntimeReason::InfluenceNotActive {
                state: subject.influence,
            }],
        });
    }
    let mut allowed = subject.allowed_uses.clone();
    if !allowed.contains(&added) {
        allowed.push(added);
        allowed.sort_by_key(|use_| RuntimeUse::rank(*use_));
    }
    let qualified = subject.qualified_for_confirmatory
        || RuntimeUse::rank(added) >= RuntimeUse::rank(EpistemicUse::CandidateEvidence);
    let mut next = RuntimeSubject::new(
        subject.subject_ref.clone(),
        subject.origin_ref.clone(),
        allowed,
        subject.influence,
        subject.retrievable,
        subject.support_revision,
        subject.state_fence.clone(),
    )?;
    next.qualified_for_confirmatory = qualified;
    Ok(next)
}

/// Context-admission boundary: admits a retrievable subject for exploratory
/// read. This is the only entry to the reachable path.
pub fn admit_context(subject: &RuntimeSubject) -> Result<AdmissionReceipt, InfluenceRuntimeError> {
    let verdict = policy_gate(subject, RuntimeUse::ExploratoryRead)?;
    if !verdict.is_allow() {
        return Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::ContextAdmission,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
        });
    }
    Ok(AdmissionReceipt {
        subject_ref: subject.subject_ref.clone(),
        subject_digest: verdict.subject_digest,
        verdict_kind: verdict.kind,
        state_fence: subject.state_fence.clone(),
    })
}

/// Pending-injection boundary: stages an admitted subject for use. Requires
/// the admission receipt for the same subject digest and state fence, and
/// re-runs the gate.
pub fn inject_pending(
    subject: &RuntimeSubject,
    admission: &AdmissionReceipt,
) -> Result<PendingReceipt, InfluenceRuntimeError> {
    let digest = subject.digest()?;
    if admission.subject_digest != digest || admission.subject_ref != subject.subject_ref {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::PendingInjection,
        });
    }
    if admission.state_fence != subject.state_fence {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::PendingInjection,
        });
    }
    if !matches!(admission.verdict_kind, RuntimeVerdictKind::Allow) {
        return Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::PendingInjection,
            subject: subject.subject_ref.clone(),
            reasons: vec![RuntimeReason::RecordNotRetrievable],
        });
    }
    let verdict = policy_gate(subject, RuntimeUse::ExploratoryRead)?;
    if !verdict.is_allow() {
        return Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::PendingInjection,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
        });
    }
    Ok(PendingReceipt {
        subject_ref: subject.subject_ref.clone(),
        subject_digest: digest,
        admission_digest: admission.digest()?,
        state_fence: subject.state_fence.clone(),
    })
}

/// Validated admission digest for a subject.
///
/// Every later stage re-validates the admission receipt from the subject
/// itself: same subject reference and digest, same state fence, and an allow
/// verdict. A forged or stale admission (matching digest but arbitrary fence,
/// or a digest from a previous subject revision) fails here.
fn validated_admission_digest(
    subject: &RuntimeSubject,
    admission: &AdmissionReceipt,
    stage: RuntimeStage,
) -> Result<String, InfluenceRuntimeError> {
    let digest = subject.digest()?;
    if admission.subject_ref != subject.subject_ref || admission.subject_digest != digest {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    if admission.state_fence != subject.state_fence {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    if !matches!(admission.verdict_kind, RuntimeVerdictKind::Allow) {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    admission
        .digest()
        .map_err(|_| InfluenceRuntimeError::Canonicalization)
}

/// Validated pending digest for a subject and its admission.
///
/// Checks the pending receipt against the subject (reference, digest, fence)
/// and binds it to the validated admission via `admission_digest`. A forged
/// pending receipt with a matching subject digest but an arbitrary fence or
/// predecessor digest fails here, as does a stale pending from a previous
/// subject revision.
fn validated_pending_digest(
    subject: &RuntimeSubject,
    pending: &PendingReceipt,
    admission: &AdmissionReceipt,
    stage: RuntimeStage,
) -> Result<String, InfluenceRuntimeError> {
    let expected_admission = validated_admission_digest(subject, admission, stage)?;
    let digest = subject.digest()?;
    if pending.subject_ref != subject.subject_ref || pending.subject_digest != digest {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    if pending.state_fence != subject.state_fence {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    if pending.admission_digest != expected_admission {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    pending
        .digest()
        .map_err(|_| InfluenceRuntimeError::Canonicalization)
}

/// Material-decision boundary: consumes a pending receipt as decision or
/// verifier input. The validated admission receipt must accompany the pending
/// receipt so the pending fence and predecessor digest are bound to the same
/// subject revision. A retrievable-but-restricted record is denied here with a
/// stated reason. Degraded-use is reported as an error carrying the degraded
/// verdict so the caller can only proceed at the stated fallback use.
pub fn decide_material(
    subject: &RuntimeSubject,
    pending: &PendingReceipt,
    admission: &AdmissionReceipt,
    requested: RuntimeUse,
) -> Result<DecisionReceipt, InfluenceRuntimeError> {
    if !matches!(
        requested,
        RuntimeUse::DecisionInput | RuntimeUse::VerifierInput
    ) {
        return Err(InfluenceRuntimeError::InvalidUseForStage {
            stage: RuntimeStage::MaterialDecision,
            requested,
        });
    }
    let digest = subject.digest()?;
    let expected_pending =
        validated_pending_digest(subject, pending, admission, RuntimeStage::MaterialDecision)?;
    if pending.subject_digest != digest || pending.subject_ref != subject.subject_ref {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::MaterialDecision,
        });
    }
    let verdict = policy_gate(subject, requested)?;
    match verdict.kind {
        RuntimeVerdictKind::Allow => Ok(DecisionReceipt {
            subject_ref: subject.subject_ref.clone(),
            subject_digest: digest,
            pending_digest: expected_pending,
            requested,
            verdict_kind: verdict.kind,
            state_fence: subject.state_fence.clone(),
        }),
        RuntimeVerdictKind::DegradedUse => Err(InfluenceRuntimeError::Degraded {
            stage: RuntimeStage::MaterialDecision,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
            fallback: verdict.allowed_fallback,
        }),
        RuntimeVerdictKind::Deny => Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::MaterialDecision,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
        }),
    }
}

/// Result-binding boundary: binds a material decision as a verifier or
/// confirmatory result. The validated pending and admission receipts must
/// accompany the decision so the decision fence and predecessor digest are
/// bound to the same subject revision, and the binding use must not exceed
/// the decision use (a `DECISION_INPUT` receipt cannot yield a
/// `VERIFIER_INPUT` binding). An exploratory-only record cannot satisfy
/// verifier or confirmatory acceptance here without a qualifying transition.
pub fn bind_result(
    subject: &RuntimeSubject,
    decision: &DecisionReceipt,
    pending: &PendingReceipt,
    admission: &AdmissionReceipt,
    requested: RuntimeUse,
) -> Result<BindingReceipt, InfluenceRuntimeError> {
    if !matches!(
        requested,
        RuntimeUse::VerifierInput | RuntimeUse::ConfirmatoryAcceptance
    ) {
        return Err(InfluenceRuntimeError::InvalidUseForStage {
            stage: RuntimeStage::ResultBinding,
            requested,
        });
    }
    let digest = subject.digest()?;
    let expected_pending =
        validated_pending_digest(subject, pending, admission, RuntimeStage::ResultBinding)?;
    if decision.subject_digest != digest || decision.subject_ref != subject.subject_ref {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::ResultBinding,
        });
    }
    if decision.state_fence != subject.state_fence {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::ResultBinding,
        });
    }
    if decision.pending_digest != expected_pending {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::ResultBinding,
        });
    }
    if !matches!(decision.verdict_kind, RuntimeVerdictKind::Allow) {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::ResultBinding,
        });
    }
    if RuntimeUse::rank(requested.required_use())
        > RuntimeUse::rank(decision.requested.required_use())
    {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::ResultBinding,
        });
    }
    let verdict = policy_gate(subject, requested)?;
    match verdict.kind {
        RuntimeVerdictKind::Allow => Ok(BindingReceipt {
            subject_ref: subject.subject_ref.clone(),
            subject_digest: digest,
            decision_digest: decision.digest()?,
            requested,
            state_fence: subject.state_fence.clone(),
        }),
        RuntimeVerdictKind::DegradedUse => Err(InfluenceRuntimeError::Degraded {
            stage: RuntimeStage::ResultBinding,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
            fallback: verdict.allowed_fallback,
        }),
        RuntimeVerdictKind::Deny => Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::ResultBinding,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
        }),
    }
}

/// Digest-bound admission receipt: context-admission boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceipt {
    pub subject_ref: String,
    pub subject_digest: String,
    pub verdict_kind: RuntimeVerdictKind,
    pub state_fence: StateFence,
}

impl AdmissionReceipt {
    pub fn digest(&self) -> Result<String, InfluenceRuntimeError> {
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceRuntimeError::Canonicalization)
    }
}

/// Digest-bound pending receipt: pending-injection boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PendingReceipt {
    pub subject_ref: String,
    pub subject_digest: String,
    pub admission_digest: String,
    pub state_fence: StateFence,
}

impl PendingReceipt {
    pub fn digest(&self) -> Result<String, InfluenceRuntimeError> {
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceRuntimeError::Canonicalization)
    }
}

/// Digest-bound decision receipt: material-decision boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    pub subject_ref: String,
    pub subject_digest: String,
    pub pending_digest: String,
    pub requested: RuntimeUse,
    pub verdict_kind: RuntimeVerdictKind,
    pub state_fence: StateFence,
}

impl DecisionReceipt {
    pub fn digest(&self) -> Result<String, InfluenceRuntimeError> {
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceRuntimeError::Canonicalization)
    }
}

/// Digest-bound binding receipt: result-binding boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingReceipt {
    pub subject_ref: String,
    pub subject_digest: String,
    pub decision_digest: String,
    pub requested: RuntimeUse,
    pub state_fence: StateFence,
}

impl BindingReceipt {
    pub fn digest(&self) -> Result<String, InfluenceRuntimeError> {
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceRuntimeError::Canonicalization)
    }
}

/// Runtime path failure. Deny and degraded-use always carry the stated gate
/// reasons; nothing on this path panics on policy input.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum InfluenceRuntimeError {
    #[error("invalid runtime field: {0}")]
    InvalidField(&'static str),
    #[error("runtime use denied")]
    Denied {
        stage: RuntimeStage,
        subject: String,
        reasons: Vec<RuntimeReason>,
    },
    #[error("runtime use degraded to a weaker allowance")]
    Degraded {
        stage: RuntimeStage,
        subject: String,
        reasons: Vec<RuntimeReason>,
        fallback: Option<RuntimeUse>,
    },
    #[error("runtime path binding mismatch")]
    BindingMismatch { stage: RuntimeStage },
    #[error("runtime use is not valid at this stage")]
    InvalidUseForStage {
        stage: RuntimeStage,
        requested: RuntimeUse,
    },
    #[error("runtime record cannot be canonically serialized")]
    Canonicalization,
}

fn text(value: &str, field: &'static str) -> Result<(), InfluenceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(InfluenceError::InvalidField(field))
    } else {
        Ok(())
    }
}
fn unique(values: &[String], field: &'static str) -> Result<(), InfluenceError> {
    let mut set = BTreeSet::new();
    if values.iter().any(|value| !set.insert(value)) {
        Err(InfluenceError::DuplicateReference(field))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum InfluenceError {
    #[error("invalid influence field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate influence reference in {0}")]
    DuplicateReference(&'static str),
    #[error("source assurance is invalid")]
    InvalidSourceAssurance,
    #[error("influence dependency closure is invalid")]
    InvalidClosure,
    #[error("influence provenance or state fence does not match")]
    FenceOrLineageMismatch,
    #[error("influence request cannot be canonically serialized")]
    Canonicalization,
    #[error("duplicate influence edge")]
    DuplicateEdge,
    #[error("unknown revocation completeness")]
    UnknownCompleteness,
    #[error("legacy resumed_visited requires an exact bounded revocation continuation")]
    LegacyResumedVisited,
    #[error("bounded revocation continuation is invalid")]
    InvalidContinuation,
    #[error("bounded revocation continuation binding mismatch")]
    ContinuationBindingMismatch,
    #[error("unsupported bounded revocation continuation schema")]
    UnsupportedContinuation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_security_contracts::{
        CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, IndependenceLevel,
        InstructionTaint, IntegrityStatus, PrivacyClass, QuarantineState,
    };

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence() -> StateFence {
        let lineage = match EpochLineageId::new(TEST_LINEAGE) {
            Ok(lineage) => lineage,
            Err(error) => panic!("valid test lineage: {error:?}"),
        };
        let Some(ordinal) = std::num::NonZeroU64::new(7) else {
            panic!("nonzero test epoch ordinal")
        };
        let epoch = match EpochId::new(lineage, ordinal) {
            Ok(epoch) => epoch,
            Err(error) => panic!("valid test epoch: {error:?}"),
        };
        let generation = match ResourceGeneration::new(3) {
            Ok(generation) => generation,
            Err(error) => panic!("valid test generation: {error:?}"),
        };
        StateFence::new(epoch, generation)
    }

    fn clean_assurance(fence: &StateFence) -> SourceAssurance {
        SourceAssurance {
            source_ref: "source:test".to_string(),
            provenance_ref: "provenance:test".to_string(),
            integrity: IntegrityStatus::Verified,
            freshness: FreshnessStatus::Current,
            competence: CompetenceLevel::DomainVerified,
            independence: IndependenceLevel::Independent,
            privacy_class: PrivacyClass::Public,
            instruction_taint: InstructionTaint::Cleared,
            allowed_epistemic_use: vec![EpistemicUse::Observation],
            allowed_effects: vec![EffectCeiling::ReadOnly],
            required_verifier: None,
            quarantine: QuarantineState::None,
            state_fence: fence.clone(),
        }
    }

    fn test_closure(fence: &StateFence, state: InfluenceState) -> InfluenceDependencyClosure {
        InfluenceDependencyClosure {
            closure_id: "closure:test".to_string(),
            root_ref: "origin:test".to_string(),
            dependent_refs: vec!["origin:test".to_string(), "derived:test".to_string()],
            invalidation_reason: if state == InfluenceState::Active {
                None
            } else {
                Some(RevocationReason::Erasure)
            },
            current_influence: state,
            state_fence: fence.clone(),
            revision: 1,
        }
    }

    fn test_request(state: InfluenceState) -> InfluenceRequest {
        let fence = test_fence();
        let policy = InfluencePolicy {
            policy_id: "policy:test".to_string(),
            revision: 1,
            state_fence: fence.clone(),
            require_verified_integrity: false,
            require_current_freshness: false,
            allow_unknown_independence: true,
            allow_instruction_taint: true,
            minimum_level: InfluenceLevel::VerifiedUse,
        };
        let provenance = ProvenanceRecord {
            subject_ref: "subject:test".to_string(),
            origin_ref: "origin:test".to_string(),
            source_assurance: clean_assurance(&fence),
            parent_refs: vec!["parent:test".to_string()],
            transformation_ref: None,
            state_fence: fence.clone(),
        };
        InfluenceRequest {
            request_id: "request:test".to_string(),
            subject_ref: "subject:test".to_string(),
            requested_level: InfluenceLevel::VerifiedUse,
            policy,
            provenance,
            dependency_closure: test_closure(&fence, state),
        }
    }

    #[test]
    fn revoked_closure_blocks_use() {
        let decision = match decide(&test_request(InfluenceState::Revoked)) {
            Ok(decision) => decision,
            Err(error) => panic!("revoked decide succeeds: {error:?}"),
        };
        assert_eq!(decision.disposition, InfluenceDisposition::Revoked);
        assert_eq!(decision.allowed_level, InfluenceLevel::Stored);
        assert!(
            decision
                .reasons
                .contains(&InfluenceReason::DependencyRevoked)
        );
    }

    #[test]
    fn revocation_output_blocks_decide() {
        let fence = test_fence();
        let receipt = match revoke(&RevocationRequest {
            request_id: "revoke:test".to_string(),
            root_ref: "origin:test".to_string(),
            reason: RevocationReason::Erasure,
            state_fence: fence.clone(),
            graph: vec![
                InfluenceEdge {
                    source_ref: "origin:test".to_string(),
                    dependent_ref: "derived:test".to_string(),
                },
                InfluenceEdge {
                    source_ref: "derived:test".to_string(),
                    dependent_ref: "leaf:test".to_string(),
                },
            ],
        }) {
            Ok(receipt) => receipt,
            Err(error) => panic!("revoke succeeds: {error:?}"),
        };
        assert!(receipt.affected_refs.contains(&"origin:test".to_string()));
        assert!(receipt.affected_refs.contains(&"derived:test".to_string()));
        assert!(receipt.affected_refs.contains(&"leaf:test".to_string()));
        for closure in &receipt.closures {
            assert_eq!(closure.current_influence, InfluenceState::Revoked);
        }
        let Some(revoked) = receipt
            .closures
            .iter()
            .find(|closure| closure.root_ref == "origin:test")
        else {
            panic!("revocation covers its root")
        };
        let mut request = test_request(InfluenceState::Active);
        request.dependency_closure = revoked.clone();
        request.provenance.origin_ref = revoked.root_ref.clone();
        request.dependency_closure.closure_id = "closure:test".to_string();
        let decision = match decide(&request) {
            Ok(decision) => decision,
            Err(error) => panic!("revoked closure decide succeeds: {error:?}"),
        };
        assert_eq!(decision.disposition, InfluenceDisposition::Revoked);
        assert_eq!(decision.allowed_level, InfluenceLevel::Stored);
    }

    #[test]
    fn unknown_closure_fails_closed() {
        let decision = match decide(&test_request(InfluenceState::Unknown)) {
            Ok(decision) => decision,
            Err(error) => panic!("unknown decide succeeds: {error:?}"),
        };
        assert_eq!(decision.disposition, InfluenceDisposition::Quarantined);
        assert_eq!(decision.allowed_level, InfluenceLevel::Stored);
        assert!(
            decision
                .reasons
                .contains(&InfluenceReason::DependencyQuarantined)
        );
    }

    #[test]
    fn quarantined_closure_quarantines() {
        let decision = match decide(&test_request(InfluenceState::Quarantined)) {
            Ok(decision) => decision,
            Err(error) => panic!("quarantined decide succeeds: {error:?}"),
        };
        assert_eq!(decision.disposition, InfluenceDisposition::Quarantined);
        assert_eq!(decision.allowed_level, InfluenceLevel::Stored);
    }

    fn runtime_subject(
        allowed: Vec<EpistemicUse>,
        influence: InfluenceState,
        retrievable: bool,
    ) -> RuntimeSubject {
        let fence = test_fence();
        match RuntimeSubject::new(
            "subject:runtime".to_string(),
            "origin:runtime".to_string(),
            allowed,
            influence,
            retrievable,
            11,
            fence,
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("valid runtime subject: {error:?}"),
        }
    }

    fn qualified_subject(allowed: Vec<EpistemicUse>) -> RuntimeSubject {
        let base = runtime_subject(allowed, InfluenceState::Active, true);
        match qualify_transition(
            &base,
            EpistemicUse::CandidateEvidence,
            "evidence:test-qualification",
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("test qualification succeeds: {error:?}"),
        }
    }

    fn deny_reasons(result: Result<DecisionReceipt, InfluenceRuntimeError>) -> Vec<RuntimeReason> {
        match result {
            Ok(_) => panic!("expected denial, got allowance"),
            Err(InfluenceRuntimeError::Denied { reasons, .. }) => reasons,
            Err(other) => panic!("expected denial, got {other:?}"),
        }
    }

    #[test]
    fn retrievable_but_restricted_denied_as_decision_input_with_reason() {
        let subject = runtime_subject(
            vec![EpistemicUse::Observation],
            InfluenceState::Active,
            true,
        );
        // Retrievable: exploratory admission through the reachable path succeeds.
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("exploratory admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("pending injection succeeds: {error:?}"),
        };
        // Restricted: the same record is denied as material decision input,
        // and the verdict states the missing allowance.
        let verdict = match policy_gate(&subject, RuntimeUse::DecisionInput) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates: {error:?}"),
        };
        assert_eq!(verdict.kind, RuntimeVerdictKind::Deny);
        let missing = verdict.reasons.iter().any(|reason| {
            matches!(
                reason,
                RuntimeReason::EpistemicUseNotAllowed {
                    requested: EpistemicUse::CandidateEvidence,
                    ..
                }
            )
        });
        assert!(
            missing,
            "denial states the missing use: {:?}",
            verdict.reasons
        );
        let reasons = deny_reasons(decide_material(
            &subject,
            &pending,
            &admission,
            RuntimeUse::DecisionInput,
        ));
        assert!(
            reasons
                .iter()
                .any(|reason| matches!(reason, RuntimeReason::EpistemicUseNotAllowed { .. }))
        );
    }

    #[test]
    fn exploratory_only_needs_qualifying_transition_for_verifier_and_confirmatory() {
        let subject = runtime_subject(
            vec![EpistemicUse::Observation],
            InfluenceState::Active,
            true,
        );
        let verifier_verdict = match policy_gate(&subject, RuntimeUse::VerifierInput) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates verifier use: {error:?}"),
        };
        assert_eq!(verifier_verdict.kind, RuntimeVerdictKind::Deny);
        assert!(
            verifier_verdict
                .reasons
                .contains(&RuntimeReason::ExploratoryOnlyCannotSatisfyVerifier)
        );
        let confirmatory_verdict = match policy_gate(&subject, RuntimeUse::ConfirmatoryAcceptance) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates confirmatory use: {error:?}"),
        };
        assert_eq!(confirmatory_verdict.kind, RuntimeVerdictKind::Deny);
        assert!(
            confirmatory_verdict
                .reasons
                .contains(&RuntimeReason::ExploratoryOnlyCannotSatisfyConfirmatory)
        );

        // Qualifying transition promotes the copy; the original stays exploratory-only.
        let qualified = match qualify_transition(
            &subject,
            EpistemicUse::CandidateEvidence,
            "evidence:analyst-review-1",
        ) {
            Ok(qualified) => qualified,
            Err(error) => panic!("qualification succeeds: {error:?}"),
        };
        assert_eq!(subject.allowed_uses, vec![EpistemicUse::Observation]);
        assert!(!subject.qualified_for_confirmatory);
        let confirmatory_after = match policy_gate(&qualified, RuntimeUse::ConfirmatoryAcceptance) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates qualified confirmatory: {error:?}"),
        };
        assert_eq!(confirmatory_after.kind, RuntimeVerdictKind::Allow);
        // Candidate evidence alone still cannot satisfy verifier input: it
        // degrades to decision input instead of allowing silently.
        let verifier_after = match policy_gate(&qualified, RuntimeUse::VerifierInput) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates qualified verifier: {error:?}"),
        };
        assert_eq!(verifier_after.kind, RuntimeVerdictKind::DegradedUse);
        assert_eq!(
            verifier_after.allowed_fallback,
            Some(RuntimeUse::DecisionInput)
        );

        let verified = match qualify_transition(
            &qualified,
            EpistemicUse::VerificationInput,
            "evidence:verifier-run-7",
        ) {
            Ok(verified) => verified,
            Err(error) => panic!("verifier qualification succeeds: {error:?}"),
        };
        let verifier_final = match policy_gate(&verified, RuntimeUse::VerifierInput) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates verified use: {error:?}"),
        };
        assert_eq!(verifier_final.kind, RuntimeVerdictKind::Allow);

        // Full reachable path succeeds only after the qualifying transition.
        let admission = match admit_context(&verified) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&verified, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let decision =
            match decide_material(&verified, &pending, &admission, RuntimeUse::DecisionInput) {
                Ok(decision) => decision,
                Err(error) => panic!("material decision succeeds: {error:?}"),
            };
        match bind_result(
            &verified,
            &decision,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => {}
            Err(error) => panic!("result binding succeeds: {error:?}"),
        }
    }

    #[test]
    fn retrieval_never_mutates_support_or_influence() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let before_digest = match subject.digest() {
            Ok(digest) => digest,
            Err(error) => panic!("subject digests: {error:?}"),
        };
        let view = retrieve_view(&subject);
        assert_eq!(view.subject_ref, subject.subject_ref);
        assert_eq!(view.allowed_uses, subject.allowed_uses);
        assert_eq!(view.influence, subject.influence);
        assert_eq!(view.support_revision, subject.support_revision);
        assert_eq!(view.retrievable, subject.retrievable);
        // Exercise the whole reachable path against the same subject value.
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let decision =
            match decide_material(&subject, &pending, &admission, RuntimeUse::DecisionInput) {
                Ok(decision) => decision,
                Err(error) => panic!("decision succeeds: {error:?}"),
            };
        match bind_result(
            &subject,
            &decision,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => {}
            Err(error) => panic!("binding succeeds: {error:?}"),
        }
        let again = retrieve_view(&subject);
        assert_eq!(again, view);
        let after_digest = match subject.digest() {
            Ok(digest) => digest,
            Err(error) => panic!("subject digests after use: {error:?}"),
        };
        assert_eq!(before_digest, after_digest);
        assert_eq!(subject.influence, InfluenceState::Active);
        assert_eq!(subject.support_revision, 11);
    }

    #[test]
    fn runtime_path_is_reachable_in_order_only() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let other = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        // A pending stage bound to one subject cannot inject another digest.
        let mut foreign = admission.clone();
        foreign.subject_ref = "subject:other".to_string();
        match inject_pending(&other, &foreign) {
            Ok(_) => panic!("foreign injection must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
        // Material decision rejects a use that does not belong at its stage.
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        match decide_material(
            &subject,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => panic!("wrong-stage use must fail"),
            Err(InfluenceRuntimeError::InvalidUseForStage { .. }) => {}
            Err(other) => panic!("expected invalid stage use, got {other:?}"),
        }
    }

    fn test_fence_with_generation(generation: u64) -> StateFence {
        let lineage = match EpochLineageId::new(TEST_LINEAGE) {
            Ok(lineage) => lineage,
            Err(error) => panic!("valid test lineage: {error:?}"),
        };
        let Some(ordinal) = std::num::NonZeroU64::new(7) else {
            panic!("nonzero test epoch ordinal")
        };
        let epoch = match EpochId::new(lineage, ordinal) {
            Ok(epoch) => epoch,
            Err(error) => panic!("valid test epoch: {error:?}"),
        };
        let generation = match ResourceGeneration::new(generation) {
            Ok(generation) => generation,
            Err(error) => panic!("valid test generation: {error:?}"),
        };
        StateFence::new(epoch, generation)
    }

    fn test_fence_alt() -> StateFence {
        test_fence_with_generation(9)
    }

    fn runtime_subject_with_fence(
        allowed: Vec<EpistemicUse>,
        influence: InfluenceState,
        retrievable: bool,
        fence: StateFence,
        support_revision: u64,
    ) -> RuntimeSubject {
        match RuntimeSubject::new(
            "subject:runtime".to_string(),
            "origin:runtime".to_string(),
            allowed,
            influence,
            retrievable,
            support_revision,
            fence,
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("valid runtime subject: {error:?}"),
        }
    }

    fn qualified_subject_with_fence(
        allowed: Vec<EpistemicUse>,
        fence: StateFence,
    ) -> RuntimeSubject {
        let base = runtime_subject_with_fence(allowed, InfluenceState::Active, true, fence, 11);
        match qualify_transition(
            &base,
            EpistemicUse::CandidateEvidence,
            "evidence:test-qualification",
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("test qualification succeeds: {error:?}"),
        }
    }

    fn expect_binding_mismatch(result: Result<(), InfluenceRuntimeError>, case: &str) {
        match result {
            Ok(()) => panic!("{case} must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("{case}: expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn inject_pending_rejects_forged_fence() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let mut forged = admission.clone();
        forged.state_fence = test_fence_alt();
        expect_binding_mismatch(
            inject_pending(&subject, &forged).map(|_| ()),
            "forged admission fence",
        );
    }

    #[test]
    fn inject_pending_rejects_stale_admission() {
        let old = qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence());
        let old_admission = match admit_context(&old) {
            Ok(admission) => admission,
            Err(error) => panic!("old admission succeeds: {error:?}"),
        };
        let new =
            qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence_alt());
        expect_binding_mismatch(
            inject_pending(&new, &old_admission).map(|_| ()),
            "stale admission from previous fence",
        );
    }

    #[test]
    fn decide_material_rejects_forged_pending_fence() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let mut forged = pending.clone();
        forged.state_fence = test_fence_alt();
        match decide_material(&subject, &forged, &admission, RuntimeUse::DecisionInput) {
            Ok(_) => panic!("forged pending fence must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn decide_material_rejects_forged_admission_digest() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let mut forged = pending.clone();
        forged.admission_digest = "0".repeat(64);
        match decide_material(&subject, &forged, &admission, RuntimeUse::DecisionInput) {
            Ok(_) => panic!("forged admission digest must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn decide_material_rejects_stale_chain() {
        let old = qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence());
        let old_admission = match admit_context(&old) {
            Ok(admission) => admission,
            Err(error) => panic!("old admission succeeds: {error:?}"),
        };
        let old_pending = match inject_pending(&old, &old_admission) {
            Ok(pending) => pending,
            Err(error) => panic!("old injection succeeds: {error:?}"),
        };
        let new =
            qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence_alt());
        let new_admission = match admit_context(&new) {
            Ok(admission) => admission,
            Err(error) => panic!("new admission succeeds: {error:?}"),
        };
        match decide_material(
            &new,
            &old_pending,
            &new_admission,
            RuntimeUse::DecisionInput,
        ) {
            Ok(_) => panic!("stale pending must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
        match decide_material(
            &new,
            &old_pending,
            &old_admission,
            RuntimeUse::DecisionInput,
        ) {
            Ok(_) => panic!("stale pending plus stale admission must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn bind_result_rejects_forged_decision_fence() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let decision =
            match decide_material(&subject, &pending, &admission, RuntimeUse::DecisionInput) {
                Ok(decision) => decision,
                Err(error) => panic!("decision succeeds: {error:?}"),
            };
        let mut forged = decision.clone();
        forged.state_fence = test_fence_alt();
        match bind_result(
            &subject,
            &forged,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => panic!("forged decision fence must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn bind_result_rejects_forged_pending_digest() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let decision =
            match decide_material(&subject, &pending, &admission, RuntimeUse::DecisionInput) {
                Ok(decision) => decision,
                Err(error) => panic!("decision succeeds: {error:?}"),
            };
        let mut forged = decision.clone();
        forged.pending_digest = "0".repeat(64);
        match bind_result(
            &subject,
            &forged,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => panic!("forged pending digest must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn bind_result_rejects_stale_chain() {
        let old = qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence());
        let old_admission = match admit_context(&old) {
            Ok(admission) => admission,
            Err(error) => panic!("old admission succeeds: {error:?}"),
        };
        let old_pending = match inject_pending(&old, &old_admission) {
            Ok(pending) => pending,
            Err(error) => panic!("old injection succeeds: {error:?}"),
        };
        let old_decision = match decide_material(
            &old,
            &old_pending,
            &old_admission,
            RuntimeUse::DecisionInput,
        ) {
            Ok(decision) => decision,
            Err(error) => panic!("old decision succeeds: {error:?}"),
        };
        let new =
            qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence_alt());
        let new_admission = match admit_context(&new) {
            Ok(admission) => admission,
            Err(error) => panic!("new admission succeeds: {error:?}"),
        };
        let new_pending = match inject_pending(&new, &new_admission) {
            Ok(pending) => pending,
            Err(error) => panic!("new injection succeeds: {error:?}"),
        };
        match bind_result(
            &new,
            &old_decision,
            &new_pending,
            &new_admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => panic!("stale decision must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
        match bind_result(
            &new,
            &old_decision,
            &old_pending,
            &old_admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => panic!("fully stale chain must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn bind_result_rejects_decision_input_for_verifier_binding() {
        let base = runtime_subject_with_fence(
            vec![EpistemicUse::CandidateEvidence],
            InfluenceState::Active,
            true,
            test_fence(),
            11,
        );
        let qualified = match qualify_transition(
            &base,
            EpistemicUse::CandidateEvidence,
            "evidence:test-qualification",
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("test qualification succeeds: {error:?}"),
        };
        let verified = match qualify_transition(
            &qualified,
            EpistemicUse::VerificationInput,
            "evidence:verifier-run-7",
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("verifier qualification succeeds: {error:?}"),
        };
        let admission = match admit_context(&verified) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&verified, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let decision_input =
            match decide_material(&verified, &pending, &admission, RuntimeUse::DecisionInput) {
                Ok(decision) => decision,
                Err(error) => panic!("decision input succeeds: {error:?}"),
            };
        assert_eq!(decision_input.requested, RuntimeUse::DecisionInput);
        match bind_result(
            &verified,
            &decision_input,
            &pending,
            &admission,
            RuntimeUse::VerifierInput,
        ) {
            Ok(_) => panic!("decision-input receipt must not yield verifier binding"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
        let verifier_decision =
            match decide_material(&verified, &pending, &admission, RuntimeUse::VerifierInput) {
                Ok(decision) => decision,
                Err(error) => panic!("verifier decision succeeds: {error:?}"),
            };
        match bind_result(
            &verified,
            &verifier_decision,
            &pending,
            &admission,
            RuntimeUse::VerifierInput,
        ) {
            Ok(_) => {}
            Err(error) => panic!("verifier decision binds verifier use: {error:?}"),
        }
        match bind_result(
            &verified,
            &decision_input,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => {}
            Err(error) => panic!("decision input binds confirmatory use: {error:?}"),
        }
    }
    #[test]
    fn bind_result_rejects_forged_decision_verdict() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let decision =
            match decide_material(&subject, &pending, &admission, RuntimeUse::DecisionInput) {
                Ok(decision) => decision,
                Err(error) => panic!("decision succeeds: {error:?}"),
            };
        let mut forged = decision.clone();
        forged.verdict_kind = RuntimeVerdictKind::DegradedUse;
        match bind_result(
            &subject,
            &forged,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => panic!("forged decision verdict must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }
}
