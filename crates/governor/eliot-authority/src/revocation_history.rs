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
//!   evidence always suppresses the same grants in the same order;
//! * no closure identity repeats with changed content: reusing an
//!   idempotency key with different canonical content is
//!   [`RevocationHistoryError::IdentityConflict`] and applies nothing
//!   (I5.27).
//!
//! An explicitly empty closure set is a complete denominator (the source
//! attests zero revocations at the stated revision), never a default. An
//! absent input (`None` at the restore boundary) is unavailable history,
//! which is not absence of revocation and refuses.
//!
//! #2966: one declared revocation origin
//!
//! A committed closure suppresses exactly the grants structurally reachable
//! from ONE declared revocation origin under the restored graph revision.
//! `InfluenceDependencyClosure::root_ref` is one untyped string and its
//! `dependent_refs` are record-supplied membership, so neither can be read
//! as authority. This module therefore never infers revocation semantics
//! from a reference:
//!
//! * the graph owner resolves `root_ref` against the bound graph into the
//!   closed [`RevocationOrigin`] value, which distinguishes a grant origin
//!   from an authority-root origin;
//! * the graph owner computes the one expected
//!   [`RevocationDenominator`](crate::grants::RevocationDenominator) for
//!   that origin and compares the committed membership against it BEFORE
//!   any suppression is derived;
//! * only then is the record admitted as an [`AdmittedRevocationClosure`],
//!   the one type suppression derivation consumes.
//!
//! An in-graph affected grant the declared origin cannot reach is the
//! distinct [`RevocationHistoryError::OriginTargetMismatch`] refusal. It is
//! never reinterpreted as a second origin, never ignored as harmless, and
//! never folded into `TargetDrift`, which reports a reachable target the
//! committed closure omitted.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_influence::RevocationBounds;
use eliot_security_contracts::{InfluenceDependencyClosure, InfluenceState, RevocationReason};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::grants::RevocationDenominator;
use crate::{AuthorityError, CapabilityGrant, GrantGraph, GrantId, validate_text};

/// Closed evidence version of the authority revocation-history closure
/// record (issue #2966, step 2).
///
/// Every [`ValidatedRevocationClosure`] is stamped with this version by
/// [`RevocationHistoryEvidence::require_current`](RevocationHistoryEvidence::require_current)
/// and every [`AdmittedRevocationClosure`] carries it through admission,
/// which refuses any other version: a closure validated under an older (or
/// newer) evidence version is never silently reinterpreted as the current
/// stronger form. The wire-carried owner namespace and the durable owner
/// receipt stay with the durable history owner and are never minted here.
pub const REVOCATION_HISTORY_EVIDENCE_VERSION: u16 = 1;

/// Explicit CURRENT revocation-history evidence observed at one durable
/// source revision.
///
/// The closures reuse the `eliot-influence` dependency-closure shape
/// read-only: this crate never evaluates influence itself. The source
/// revision is the durable revocation-history revision the closures were
/// read at (carried by the `RecordAuthorityRevocation` named-mutation
/// history and served by the revocation-history named read); every closure
/// must carry exactly that revision.
///
/// The shape carries no owner namespace and no typed origin, so it is a
/// shared observation DTO, not the authority recovery contract: the typed
/// origin and the bound-graph denominator are established at restore by
/// [`AdmittedRevocationClosure`].
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
    /// declared affected reference set per closure, in closure order.
    ///
    /// This step decodes and shape-checks the history only. It deliberately
    /// does not decide which grants the affected references reach: that is
    /// the origin-bound denominator comparison
    /// `GrantGraph::admit_origin_bound_closure`, which runs before any
    /// suppression is derived.
    ///
    /// One closure identity presented twice with changed content is
    /// [`RevocationHistoryError::IdentityConflict`]: the committed result
    /// is authoritative and nothing is applied. An identical repeat still
    /// violates the strictly-increasing shape and refuses as unknown, and
    /// an out-of-order identity refuses as unknown; the refusal set is
    /// unchanged, only the conflict cause is named.
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
        let mut previous: Option<&InfluenceDependencyClosure> = None;
        for closure in &self.closures {
            if let Some(previous) = previous
                && previous.closure_id.as_str() >= closure.closure_id.as_str()
            {
                if previous.closure_id == closure.closure_id {
                    let previous_digest = closure_canonical_digest(previous)?;
                    let digest = closure_canonical_digest(closure)?;
                    if previous_digest != digest {
                        return Err(RevocationHistoryError::IdentityConflict(
                            ClosureIdentityConflict {
                                closure_id: closure.closure_id.clone(),
                                field: conflicted_closure_field(previous, closure)
                                    .unwrap_or("closure.canonical_content"),
                            },
                        ));
                    }
                }
                return Err(RevocationHistoryError::UnknownHistory);
            }
            previous = Some(closure);
        }
        self.closures
            .iter()
            .map(|closure| ValidatedRevocationClosure::require_current(closure, self))
            .collect()
    }
}

/// First canonical field on which two closures sharing one `closure_id`
/// disagree, if any.
///
/// Dependent order is spelling, not content: validation absorbs the
/// dependents into a set and every downstream decision is
/// order-insensitive, so only the sorted membership is compared.
/// Anything else — origin, reason, state, fence, or revision — is
/// committed content under I5.27, and a difference is an identity
/// conflict, never a merge.
fn conflicted_closure_field(
    previous: &InfluenceDependencyClosure,
    closure: &InfluenceDependencyClosure,
) -> Option<&'static str> {
    if previous.root_ref != closure.root_ref {
        return Some("closure.root_ref");
    }
    let mut previous_dependents: Vec<&str> =
        previous.dependent_refs.iter().map(String::as_str).collect();
    let mut dependents: Vec<&str> = closure.dependent_refs.iter().map(String::as_str).collect();
    previous_dependents.sort_unstable();
    dependents.sort_unstable();
    if previous_dependents != dependents {
        return Some("closure.dependent_refs");
    }
    if previous.invalidation_reason != closure.invalidation_reason {
        return Some("closure.invalidation_reason");
    }
    if previous.current_influence != closure.current_influence {
        return Some("closure.current_influence");
    }
    if previous.state_fence != closure.state_fence {
        return Some("closure.state_fence");
    }
    if previous.revision != closure.revision {
        return Some("closure.revision");
    }
    None
}

/// Canonical preimage of one exact revocation-closure presentation.
/// Private on purpose: it is the digest input, not a wire contract.
///
/// Dependent order is spelling, not content (see
/// [`conflicted_closure_field`]), so the preimage carries the sorted
/// membership; the committed affected set is exactly this origin plus
/// these dependents. Every other presented field is committed content.
#[derive(Serialize)]
struct RevocationClosureCanonicalPreimage<'a> {
    closure_id: &'a str,
    root_ref: &'a str,
    dependent_refs: Vec<&'a str>,
    invalidation_reason: Option<RevocationReason>,
    current_influence: InfluenceState,
    state_fence: &'a StateFence,
    revision: u64,
}

/// Canonical request digest of one exact revocation-closure presentation:
/// the identity, origin, sorted dependents, reason, state, fence, and
/// revision the wire record presented. An unserializable presentation is
/// unknown evidence, never a defaulted hash.
fn closure_canonical_digest(
    closure: &InfluenceDependencyClosure,
) -> Result<String, RevocationHistoryError> {
    let mut dependent_refs: Vec<&str> = closure.dependent_refs.iter().map(String::as_str).collect();
    dependent_refs.sort_unstable();
    let bytes = canonical_json_bytes(&RevocationClosureCanonicalPreimage {
        closure_id: closure.closure_id.as_str(),
        root_ref: closure.root_ref.as_str(),
        dependent_refs,
        invalidation_reason: closure.invalidation_reason,
        current_influence: closure.current_influence,
        state_fence: &closure.state_fence,
        revision: closure.revision,
    })
    .map_err(|_| RevocationHistoryError::UnknownHistory)?;
    Ok(sha256_hex(&bytes))
}

/// One CURRENT revocation closure with its exact declared reference set.
///
/// The affected set is what the durable record CLAIMS: the origin reference
/// plus every dependent the record supplied, kept verbatim. It is not a
/// validated denominator — set semantics here only absorb influence cycles
/// and self-edges so decoding terminates — and no member of it suppresses
/// anything until the graph owner has proven it reachable from the one
/// declared [`RevocationOrigin`] (see [`AdmittedRevocationClosure`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRevocationClosure {
    /// Stable closure identity carried by the evidence.
    pub closure_id: String,
    /// Origin reference as the record spelled it. It is untyped on the wire
    /// and is resolved against the bound graph by
    /// `GrantGraph::resolve_revocation_origin`;
    /// nothing here reads it as a grant or as an authority root.
    pub root_ref: String,
    /// Exact declared affected references: the origin reference plus every
    /// dependent. Retained verbatim for reconciliation and forensics.
    pub affected: BTreeSet<String>,
    /// Why the origin was invalidated.
    pub reason: RevocationReason,
    /// The closure's own committed revision: nonzero and never newer than
    /// the durable source revision it was observed at.
    pub revision: u64,
    /// Durable revocation-history revision the closure was observed at: the
    /// recovery reference this validation is bound to.
    pub source_revision: u64,
    /// Canonical request digest of the exact presented bytes: identity,
    /// origin, sorted dependents, reason, state, fence, and revision.
    pub canonical_request_digest: String,
    /// Evidence version this validation was proven under. Admission
    /// requires [`REVOCATION_HISTORY_EVIDENCE_VERSION`], so a value
    /// reaching admission by any path other than `require_current` under
    /// the current version is refused rather than reinterpreted.
    pub evidence_version: u16,
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
        // CURRENT evidence may carry older committed closures, but never a
        // zero or future revision.
        if closure.revision == 0 || closure.revision > evidence.source_revision {
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
        let canonical_request_digest = closure_canonical_digest(closure)?;
        let mut affected = BTreeSet::new();
        affected.insert(closure.root_ref.clone());
        affected.extend(closure.dependent_refs.iter().cloned());
        Ok(Self {
            closure_id: closure.closure_id.clone(),
            root_ref: closure.root_ref.clone(),
            affected,
            reason,
            revision: closure.revision,
            source_revision: evidence.source_revision,
            canonical_request_digest,
            evidence_version: REVOCATION_HISTORY_EVIDENCE_VERSION,
        })
    }
}

/// Typed authority-root reference at the authority recovery boundary.
///
/// `InfluenceDependencyClosure::root_ref` carries one untyped string, so a
/// root reference has no type of its own on the wire. This is the closed
/// typed form a resolved [`RevocationOrigin`] carries: it is validated
/// exactly like every other authority reference in this crate and it mints
/// nothing.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityRootRef(String);

impl AuthorityRootRef {
    /// Validates one non-blank, control-character-free root reference.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthorityError> {
        let value = value.into();
        validate_text(&value, "authority_root_ref")?;
        Ok(Self(value))
    }

    /// The exact reference text this value carries.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuthorityRootRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The ONE declared revocation origin every restored suppression binds to.
///
/// A committed closure suppresses exactly the grants structurally reachable
/// from this origin under the restored graph revision. A grant origin and an
/// authority-root origin are different authorities with different
/// denominators, so the kind is part of the value. Nothing in this crate
/// infers the kind from the spelling of a reference, from a name prefix, or
/// from "it matches a grant, otherwise it is a root": the kind is resolved
/// by
/// `GrantGraph::resolve_revocation_origin`
/// against the bound graph, which refuses a name that resolves to no entity
/// of this graph and a name that resolves to two.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationOrigin {
    /// A revoked grant. Its denominator is that grant's own descendant
    /// closure: the grant, its same-root descendants, and only the cross-root
    /// descendants reached through exact admitted transition evidence.
    Grant(GrantId),
    /// A revoked authority root. Its denominator is every admitted grant that
    /// root owns, closed under their authorized descendant paths. The root
    /// marker is retained here, separately from the grant members, so the
    /// marker itself is never counted as a grant member and a second origin
    /// can never stand in for a member.
    AuthorityRoot(AuthorityRootRef),
}

impl RevocationOrigin {
    /// The exact reference the closure declared, whatever its kind. It is
    /// diagnostic text for the typed refusals, never a lookup key.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Grant(grant_id) => grant_id.as_str(),
            Self::AuthorityRoot(root_ref) => root_ref.as_str(),
        }
    }
}

impl fmt::Display for RevocationOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grant(_) => formatter.write_str("grant origin ")?,
            Self::AuthorityRoot(_) => formatter.write_str("authority-root origin ")?,
        }
        formatter.write_str(self.as_str())
    }
}

/// The exact in-graph target a committed closure claimed that its one
/// declared revocation origin cannot reach.
///
/// The refusal keeps the closure identity, the declared origin, and the
/// offending reference, so the malformed record stays available for
/// reconciliation and forensics: A0.3 "hidden rewriting of provenance or
/// history" fails closed, and the record is never deleted, normalized away,
/// split, or rewritten as if it had always been valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginTargetMismatch {
    /// Stable identity of the closure that declared the extra target.
    pub closure_id: String,
    /// The one declared origin the extra target is not reachable from.
    pub origin: RevocationOrigin,
    /// The exact in-graph grant reference the closure claimed.
    pub target: String,
}

impl fmt::Display for OriginTargetMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "revocation closure {} claims {} which is not reachable from the declared origin {}",
            self.closure_id, self.target, self.origin
        )
    }
}

/// One closure identity presented twice with changed committed content.
///
/// I5.27: idempotency is defined over canonical bytes, so reusing an
/// idempotency key with different canonical content returns
/// `IDENTITY_CONFLICT` and performs no transition. The committed result
/// is authoritative; the second presentation is refused, never merged
/// and never re-applied under the same identity. The `field` coordinate
/// names the first canonical field that disagrees, so the refusal stays
/// bounded and redacted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureIdentityConflict {
    /// Stable closure identity presented twice with different content.
    pub closure_id: String,
    /// First canonical closure field that disagrees.
    pub field: &'static str,
}

impl fmt::Display for ClosureIdentityConflict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "revocation closure {} reuses its identity with changed content at {}",
            self.closure_id, self.field
        )
    }
}

/// One committed closure whose affected membership is proven to lie inside
/// the denominator of exactly one declared [`RevocationOrigin`].
///
/// The only constructor is [`Self::admit`], which is crate-private and
/// reached from the graph owner after the origin-bound denominator
/// comparison has succeeded. There is no way to build this value from raw
/// `dependent_refs` membership, so suppression derivation cannot consume an
/// unvalidated record and a record-supplied member can never become a second
/// implicit origin. The admission binds evidence version, closure identity,
/// typed origin, reason, the expected denominator (members, verified
/// crossings, quarantined frontier, completeness, revision, and fence), the
/// unfiltered committed membership, the declared traversal bounds, the
/// durable source revision, the closure revision, and the canonical request
/// digest of the exact presented bytes, so the admitted value identifies its
/// own evidence version and its own evidence.
///
/// Two coordinates stay with the durable history owner and are never minted
/// here: a wire-carried owner namespace (this crate binds the namespace only
/// by resolving the declared origin against the bound graph) and a canonical
/// durable receipt (minting one here would be a second canonical owner).
/// Both need the durable-history-owner version bump and pre-partition across
/// the evidence constructors; until then a foreign or unscoped reference
/// refuses rather than being reinterpreted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedRevocationClosure {
    /// Stable closure identity carried by the evidence.
    pub closure_id: String,
    /// The one declared origin every suppression from this closure binds to.
    pub origin: RevocationOrigin,
    /// Why the origin was invalidated.
    pub reason: RevocationReason,
    /// The expected denominator for `origin` at the restored graph revision
    /// and fence: expected members, owner-verified cross-root members, the
    /// quarantined frontier, omissions, completeness, revision and fence.
    pub denominator: RevocationDenominator,
    /// The closure's own declared affected references, unfiltered.
    pub committed_members: BTreeSet<String>,
    /// Declared traversal bounds the expected denominator was proven
    /// complete under. The completeness claim above is meaningless
    /// without them: a denominator proven whole under wider bounds is a
    /// different proof.
    pub bounds: RevocationBounds,
    /// Durable revocation-history revision the closure was observed at.
    pub source_revision: u64,
    /// The closure's own committed revision at that source revision.
    pub closure_revision: u64,
    /// Canonical request digest of the exact presented bytes this admission
    /// was proven from: identity, origin, sorted dependents, reason,
    /// state, fence, and revision.
    pub canonical_request_digest: String,
    /// Evidence version the admission was proven under, carried from the
    /// validated closure so the admitted value identifies the evidence
    /// version its proof ran under.
    pub evidence_version: u16,
}

impl AdmittedRevocationClosure {
    /// The single construction site, callable only by the graph owner once
    /// the committed membership has been proven to lie inside
    /// `denominator`.
    ///
    /// The validated closure must carry the current
    /// [`REVOCATION_HISTORY_EVIDENCE_VERSION`]: a value built by any path
    /// other than current-form validation (a stale durable restore, a
    /// hand-built record) is unknown evidence, never silently admitted as
    /// the current stronger form.
    pub(crate) fn admit(
        closure: &ValidatedRevocationClosure,
        origin: RevocationOrigin,
        denominator: RevocationDenominator,
        bounds: RevocationBounds,
    ) -> Result<Self, RevocationHistoryError> {
        if closure.evidence_version != REVOCATION_HISTORY_EVIDENCE_VERSION {
            return Err(RevocationHistoryError::UnknownHistory);
        }
        Ok(Self {
            closure_id: closure.closure_id.clone(),
            origin,
            reason: closure.reason,
            denominator,
            committed_members: closure.affected.clone(),
            bounds,
            source_revision: closure.source_revision,
            closure_revision: closure.revision,
            canonical_request_digest: closure.canonical_request_digest.clone(),
            evidence_version: closure.evidence_version,
        })
    }
}

/// How one grant was suppressed by committed revocation history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionCause {
    /// This grant id is one of the targets the committed closure named, and
    /// the declared origin's denominator contains it.
    Direct,
    /// This grant is not itself named by the committed closure; it is
    /// suppressed because the declared origin is the authority root that
    /// owns it, so the retained root marker stands for it.
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
    /// Admitted closure whose declared origin reached this grant.
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
/// closures) refuse without restoring anything. An origin that resolves to
/// no entity of the bound graph, or to two, refuses as unknown evidence
/// rather than guessing a revocation kind from a reference's spelling, as
/// does a dependent reference that resolves to nothing in this graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationHistoryError {
    /// No revocation-history evidence was supplied.
    MissingHistory,
    /// The evidence fence or revision is not current for this restore.
    StaleHistory,
    /// A closure is invalid, unordered, or not terminal revocation evidence;
    /// its declared origin resolves to no entity of the bound graph, or to
    /// two; a dependent reference it names resolves to nothing in this
    /// graph; or it carries an evidence version this crate did not
    /// validate. A lookup miss proves nothing about another graph: an
    /// unresolvable reference in this graph's committed closure is unknown
    /// evidence, never a no-op.
    UnknownHistory,
    /// A committed closure names an in-graph target that the one declared
    /// revocation origin cannot reach. Distinct from `TargetDrift`, which
    /// reports a reachable target the closure omitted.
    OriginTargetMismatch(OriginTargetMismatch),
    /// One closure identity was presented twice in a single evidence input
    /// with different committed content: changed origin, affected set,
    /// reason, state, fence, or revision. The committed result is
    /// authoritative and nothing is applied. Exact replay across restores
    /// returns the same suppression result by construction; comparing one
    /// restore against a previous one needs the durable history owner,
    /// which this pure crate is not.
    IdentityConflict(ClosureIdentityConflict),
    /// The bounded evaluator rejected a typed request, graph, fence, or
    /// continuation before any suppression could be derived.
    BoundedRevocation(eliot_influence::InfluenceError),
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
                "authority revocation history is unknown: a closure is invalid, unordered, not a terminal revocation, declares an origin that does not resolve to exactly one entity of this graph, or names a dependent reference that resolves to no entity of this graph",
            ),
            Self::OriginTargetMismatch(mismatch) => {
                write!(formatter, "revocation origin target mismatch: {mismatch}")
            }
            Self::IdentityConflict(conflict) => {
                write!(formatter, "revocation identity conflict: {conflict}")
            }
            Self::BoundedRevocation(error) => {
                write!(formatter, "bounded revocation evidence refused: {error}")
            }
            Self::InvalidSnapshot(error) => {
                write!(formatter, "authority grant snapshot is invalid: {error}")
            }
        }
    }
}

impl Error for RevocationHistoryError {}

/// Derives the exact suppression set for one restored graph from closures
/// that already passed origin-bound denominator validation.
///
/// Only the one validated origin traversal of an
/// [`AdmittedRevocationClosure`] can suppress. A grant is a candidate only
/// when it is a member of that origin's denominator, so a reference a
/// record named but the origin cannot reach is not a suppression here and
/// never takes its descendants with it; it was already refused by
/// [`RevocationHistoryError::OriginTargetMismatch`]. Grants are visited in
/// grant-id order and delegation ancestors resolve through memoized parent
/// walks (the graph is acyclic by construction, so every walk terminates).
pub(crate) fn derive_suppressions(
    graph: &GrantGraph,
    admitted: &[AdmittedRevocationClosure],
) -> Vec<SuppressedGrant> {
    let mut memoized: BTreeMap<String, Option<SuppressedGrant>> = BTreeMap::new();
    let mut suppressed = Vec::new();
    for grant_id in graph.ordered_grant_ids() {
        if let Some(entry) = suppression_of(graph, admitted, &mut memoized, &grant_id) {
            suppressed.push(entry);
        }
    }
    suppressed
}

fn suppression_of(
    graph: &GrantGraph,
    admitted: &[AdmittedRevocationClosure],
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
    let entry = admitted
        .iter()
        .find_map(|closure| named_or_root_owned(closure, grant))
        .or_else(|| inherited_suppression(graph, admitted, memoized, grant));
    memoized.insert(grant_id.to_owned(), entry.clone());
    entry
}

/// The two causes that follow from the declared origin itself rather than
/// from lineage: a target the committed closure named, and a grant the
/// declared authority-root origin owns. Both are gated on the grant being a
/// member of that one origin's denominator.
fn named_or_root_owned(
    closure: &AdmittedRevocationClosure,
    grant: &CapabilityGrant,
) -> Option<SuppressedGrant> {
    if !closure
        .denominator
        .members
        .contains(grant.grant_id.as_str())
    {
        return None;
    }
    let cause = if closure.committed_members.contains(grant.grant_id.as_str()) {
        SuppressionCause::Direct
    } else if let RevocationOrigin::AuthorityRoot(root_ref) = &closure.origin
        && root_ref.as_str() == grant.authority_root_ref
    {
        SuppressionCause::Origin
    } else {
        return None;
    };
    Some(SuppressedGrant {
        grant_id: grant.grant_id.to_string(),
        closure_id: closure.closure_id.clone(),
        cause,
    })
}

fn inherited_suppression(
    graph: &GrantGraph,
    admitted: &[AdmittedRevocationClosure],
    memoized: &mut BTreeMap<String, Option<SuppressedGrant>>,
    grant: &CapabilityGrant,
) -> Option<SuppressedGrant> {
    // The admission comparison has already proven that every denominator
    // member is either named by the committed closure, owned by the declared
    // authority root, or inherits from one of those, so a member that
    // reaches this arm always finds a suppressed ancestor.
    let mut cursor = grant.parent_grant_id.as_ref().map(GrantId::as_str);
    while let Some(parent_id) = cursor {
        if let Some(parent) = suppression_of(graph, admitted, memoized, parent_id) {
            return Some(SuppressedGrant {
                grant_id: grant.grant_id.to_string(),
                closure_id: parent.closure_id,
                cause: SuppressionCause::Transitive(parent_id.to_owned()),
            });
        }
        cursor = graph
            .grant(parent_id)?
            .parent_grant_id
            .as_ref()
            .map(GrantId::as_str);
    }
    None
}
