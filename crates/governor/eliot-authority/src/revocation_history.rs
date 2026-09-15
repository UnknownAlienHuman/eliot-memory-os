//! Transitive influence-revocation evidence for authority recovery.
//!
//! `eliot-authority` stays the pure decision owner: this module validates an
//! explicit CURRENT revocation-history evidence input (one or more
//! `eliot-influence` dependency closures plus the durable source revision
//! they were observed at) and derives the exact grant set suppressed by
//! committed influence revocations. It mints no authority, persists nothing,
//! and never synthesizes an empty "all clear" closure: missing, stale, or
//! unknown evidence is a typed refusal to restore.
//!
//! A CURRENT evidence input satisfies all of the following:
//!
//! * the evidence fence validates and is the exact recovery fence checked by
//!   the caller (same origin, scope, fence, and epoch);
//! * the source revision is nonzero and every closure carries exactly that
//!   revision (no target revision drift between a closure and its source);
//! * every closure validates, names a non-blank origin, carries a
//!   non-empty affected set, and reports a terminal `Revoked` influence
//!   state with its invalidation reason;
//! * closures arrive in strictly increasing `closure_id` order, so the same
//!   evidence always suppresses the same grants in the same order.
//!
//! An explicitly empty closure set is a complete denominator (the source
//! attests zero revocations at the stated revision), never a default. An
//! absent input (`None` at the restore boundary) is unavailable history,
//! which is not absence of revocation and refuses.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use eliot_contracts::StateFence;
use eliot_security_contracts::{InfluenceDependencyClosure, InfluenceState, RevocationReason};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AuthorityError, GrantGraph, GrantId, validate_text};

/// Explicit CURRENT revocation-history evidence observed at one durable
/// source revision.
///
/// The closures reuse the `eliot-influence` dependency-closure shape
/// read-only: this crate never evaluates influence itself. The source
/// revision is the durable revocation-history revision the closures were
/// read at (carried by the `RecordAuthorityRevocation` named-mutation
/// history and served by the revocation-history named read); every closure
/// must carry exactly that revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationHistoryEvidence {
    /// Exact fence the history was observed at.
    pub state_fence: StateFence,
    /// Durable revocation-history revision; must be nonzero.
    pub source_revision: u64,
    /// CURRENT committed revocation closures in strictly increasing
    /// `closure_id` order. Empty attests zero revocations at
    /// `source_revision`.
    pub closures: Vec<InfluenceDependencyClosure>,
}

impl RevocationHistoryEvidence {
    /// Validates that this evidence is CURRENT and returns the exact
    /// affected set per closure, in closure order.
    ///
    /// Missing evidence is expressed by passing `None` at the restore
    /// boundary (see [`RevocationHistoryError::MissingHistory`]); this
    /// method validates a supplied input only.
    pub fn require_current(
        &self,
    ) -> Result<Vec<ValidatedRevocationClosure>, RevocationHistoryError> {
        self.state_fence
            .validate()
            .map_err(|_| RevocationHistoryError::StaleHistory)?;
        if self.source_revision == 0 {
            return Err(RevocationHistoryError::StaleHistory);
        }
        let mut previous: Option<&str> = None;
        for closure in &self.closures {
            if let Some(previous) = previous
                && previous >= closure.closure_id.as_str()
            {
                return Err(RevocationHistoryError::UnknownHistory);
            }
            previous = Some(closure.closure_id.as_str());
        }
        self.closures
            .iter()
            .map(|closure| ValidatedRevocationClosure::require_current(closure, self))
            .collect()
    }
}

/// One CURRENT revocation closure with its exact affected reference set.
///
/// The affected set always contains the revoked origin itself plus every
/// dependent reported by the closure; set semantics absorb influence
/// cycles and self-edges so traversal terminates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRevocationClosure {
    /// Stable closure identity carried by the evidence.
    pub closure_id: String,
    /// Revoked origin named by the closure.
    pub root_ref: String,
    /// Exact affected references: the origin plus every dependent.
    pub affected: BTreeSet<String>,
    /// Why the origin was invalidated.
    pub reason: RevocationReason,
}

impl ValidatedRevocationClosure {
    fn require_current(
        closure: &InfluenceDependencyClosure,
        evidence: &RevocationHistoryEvidence,
    ) -> Result<Self, RevocationHistoryError> {
        closure
            .validate()
            .map_err(|_| RevocationHistoryError::UnknownHistory)?;
        if closure.state_fence != evidence.state_fence {
            return Err(RevocationHistoryError::StaleHistory);
        }
        if closure.revision != evidence.source_revision {
            return Err(RevocationHistoryError::StaleHistory);
        }
        if closure.current_influence != InfluenceState::Revoked {
            return Err(RevocationHistoryError::UnknownHistory);
        }
        let Some(reason) = closure.invalidation_reason else {
            return Err(RevocationHistoryError::UnknownHistory);
        };
        for dependent in &closure.dependent_refs {
            validate_text(dependent, "dependent_ref")
                .map_err(|_| RevocationHistoryError::UnknownHistory)?;
        }
        let mut affected = BTreeSet::new();
        affected.insert(closure.root_ref.clone());
        affected.extend(closure.dependent_refs.iter().cloned());
        Ok(Self {
            closure_id: closure.closure_id.clone(),
            root_ref: closure.root_ref.clone(),
            affected,
            reason,
        })
    }
}

/// How one grant was suppressed by revocation history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionCause {
    /// This grant id is named in the closure affected set.
    Direct,
    /// This grant's authority origin is named in the affected set.
    Origin,
    /// A delegation ancestor was suppressed; carries the nearest suppressed
    /// ancestor grant id.
    Transitive(String),
}

/// One grant suppressed by committed revocation history during restore.
///
/// Suppressed grants are retained with their full lineage (never deleted);
/// they join the restored revoked set so no effective path can revive them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SuppressedGrant {
    /// Suppressed grant identity.
    pub grant_id: String,
    /// Closure whose affected set suppressed this grant.
    pub closure_id: String,
    /// How the closure reached this grant.
    pub cause: SuppressionCause,
}

/// Restored grant graph with the exact history-suppressed set.
#[derive(Clone, Debug)]
pub struct GrantRestoreOutcome {
    /// Restored graph with history suppressions applied to its revoked set.
    pub graph: GrantGraph,
    /// Every history-suppressed grant in grant-id order with its reason.
    pub suppressed: Vec<SuppressedGrant>,
}

/// Typed refusal to restore authority under revocation-history evidence.
///
/// Unavailable history is not absence of revocation: only an explicit
/// CURRENT input restores. Stale inputs (fence mismatch, zero or drifted
/// revision) and unknown inputs (invalid, unordered, or non-revoked
/// closures) refuse without restoring anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationHistoryError {
    /// No revocation-history evidence was supplied.
    MissingHistory,
    /// The evidence fence or revision is not current for this restore.
    StaleHistory,
    /// A closure is invalid, unordered, or not terminal revocation evidence.
    UnknownHistory,
    /// The grant snapshot itself is malformed.
    InvalidSnapshot(AuthorityError),
}

impl fmt::Display for RevocationHistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHistory => formatter.write_str(
                "authority revocation history is unavailable; unavailable history is not absence of revocation",
            ),
            Self::StaleHistory => formatter.write_str(
                "authority revocation history is stale: fence, source revision, or closure revision drifted",
            ),
            Self::UnknownHistory => formatter.write_str(
                "authority revocation history is unknown: a closure is invalid, unordered, or not a terminal revocation",
            ),
            Self::InvalidSnapshot(error) => {
                write!(formatter, "authority grant snapshot is invalid: {error}")
            }
        }
    }
}

impl Error for RevocationHistoryError {}

/// Derives the exact suppression set for one restored graph.
///
/// Grants are visited in grant-id order; delegation ancestors resolve
/// through memoized parent walks (the graph is acyclic by construction, so
/// every walk terminates). Affected references naming no grant in this
/// graph suppress nothing here: they belong to another graph's denominator
/// and never create authority.
pub(crate) fn derive_suppressions(
    graph: &GrantGraph,
    closures: &[ValidatedRevocationClosure],
) -> Vec<SuppressedGrant> {
    let mut affected: BTreeMap<&str, &ValidatedRevocationClosure> = BTreeMap::new();
    for closure in closures {
        for reference in &closure.affected {
            affected.entry(reference.as_str()).or_insert(closure);
        }
    }
    let mut memoized: BTreeMap<String, Option<SuppressedGrant>> = BTreeMap::new();
    let mut suppressed = Vec::new();
    for grant_id in graph.ordered_grant_ids() {
        if let Some(entry) = suppression_of(graph, &affected, &mut memoized, &grant_id) {
            suppressed.push(entry);
        }
    }
    suppressed
}

fn suppression_of(
    graph: &GrantGraph,
    affected: &BTreeMap<&str, &ValidatedRevocationClosure>,
    memoized: &mut BTreeMap<String, Option<SuppressedGrant>>,
    grant_id: &str,
) -> Option<SuppressedGrant> {
    if let Some(cached) = memoized.get(grant_id) {
        return cached.clone();
    }
    // Insert a temporary miss first so a delegation cycle (rejected at
    // construction, but defended here) terminates instead of recursing.
    memoized.insert(grant_id.to_owned(), None);
    let grant = graph.grant(grant_id)?;
    let direct = affected.get(grant_id).map(|closure| SuppressedGrant {
        grant_id: grant_id.to_owned(),
        closure_id: closure.closure_id.clone(),
        cause: SuppressionCause::Direct,
    });
    let entry = direct.or_else(|| {
        affected
            .get(grant.authority_root_ref.as_str())
            .map(|closure| SuppressedGrant {
                grant_id: grant_id.to_owned(),
                closure_id: closure.closure_id.clone(),
                cause: SuppressionCause::Origin,
            })
    });
    let entry = entry.or_else(|| {
        let mut cursor = grant.parent_grant_id.as_ref().map(GrantId::as_str);
        while let Some(parent_id) = cursor {
            match suppression_of(graph, affected, memoized, parent_id) {
                Some(parent_suppression) => {
                    return Some(SuppressedGrant {
                        grant_id: grant_id.to_owned(),
                        closure_id: parent_suppression.closure_id,
                        cause: SuppressionCause::Transitive(parent_id.to_owned()),
                    });
                }
                None => {
                    cursor = graph
                        .grant(parent_id)?
                        .parent_grant_id
                        .as_ref()
                        .map(GrantId::as_str);
                }
            }
        }
        None
    });
    memoized.insert(grant_id.to_owned(), entry.clone());
    entry
}
