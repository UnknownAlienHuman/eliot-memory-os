//! Canonical content addresses for versioned authority revocation-history evidence.
//!
//! Issue #2966, step 2: the durable history producer (the Kernel history
//! projector) declares the committed affected-member digest and count and the
//! canonical request hash, and the restore consumer (`eliot-authority`)
//! recomputes and compares all three. That comparison binds the restore to
//! the served bytes only when both sides canonicalize identically, so this
//! module is the ONE definition of the affected-member set, its digest, and
//! the canonical closure preimage. A second local preimage anywhere else
//! would silently unbind the comparison it claims.
//!
//! I5.27: idempotency is defined over canonical bytes, and fields affecting
//! authority, scope, ordering, privacy or effect cannot be omitted or
//! defaulted silently. The canonical preimage therefore covers every
//! presented coordinate: evidence version, closure identity, owner
//! namespace, origin, sorted dependents, reason, terminal state, fence,
//! revision, traversal bounds, disposition, sorted omissions, and the
//! affected-member count and digest. Only the declared canonical digest
//! string itself is not part of its own preimage; the consumer compares it
//! as presented content.

use std::collections::BTreeSet;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use serde::Serialize;

use crate::{InfluenceState, RevocationReason};

/// Closed evidence version of the authority revocation-history closure
/// record (issue #2966, step 2).
///
/// The version lives with the shared codec because the durable producer
/// and the restore consumer must name the same contract: every served row
/// and every validated closure declares this version, and any other
/// declared version refuses as an unsupported schema before a protected
/// field is read, so a closure validated under an older (or newer)
/// evidence version is never silently reinterpreted as the current
/// stronger form.
///
/// Version 1 was the observation DTO, which carried no owner namespace,
/// declared bounds, declared disposition, committed affected-member digest
/// or count, and no declared omissions. Those bytes are not migrated: the
/// durable history owner pre-partitions its evidence under this version,
/// and a v1 presentation is refused rather than read with defaults.
pub const REVOCATION_HISTORY_EVIDENCE_VERSION: u16 = 2;

/// Canonical spelling of the `Complete` disposition inside the digest preimage.
///
/// The served row and the validated evidence each map their own disposition
/// enum to these spellings; the digest then proves the two mappings agree,
/// so a translation slip refuses instead of admitting under a completeness
/// the producer never declared.
pub const REVOCATION_DISPOSITION_COMPLETE: &str = "complete";
/// Canonical spelling of the `Partial` disposition inside the digest preimage.
pub const REVOCATION_DISPOSITION_PARTIAL: &str = "partial";
/// Canonical spelling of the `Unknown` disposition inside the digest preimage.
pub const REVOCATION_DISPOSITION_UNKNOWN: &str = "unknown";

/// Traversal bounds as digest input: the seven limits by value, never an engine type.
///
/// Both sides destructure their own bounds value into this view; the digest
/// proves the two views agree. Digest input only, never a wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RevocationClosureDigestBounds {
    /// Maximum admitted nodes.
    pub max_nodes: u64,
    /// Maximum examined edges.
    pub max_edges: u64,
    /// Maximum traversal depth.
    pub max_depth: u64,
    /// Maximum admitted result members.
    pub max_result: u64,
    /// Maximum cumulative work units.
    pub max_work: u64,
    /// Maximum outstanding frontier width.
    pub max_frontier: u64,
    /// Maximum resume rounds.
    pub max_time: u64,
}

/// Full canonical input of one closure presentation.
///
/// Every field is a presented coordinate the producer declares and the
/// consumer recomputes; none has a default. Dependent and omission order is
/// spelling, not content, so the digest sorts both.
#[derive(Clone, Debug)]
pub struct RevocationClosureDigestInput<'a> {
    /// Declared evidence version.
    pub evidence_version: u16,
    /// Stable closure identity.
    pub closure_id: &'a str,
    /// Declared graph/snapshot owner namespace.
    pub owner_namespace: &'a str,
    /// Origin reference as the record spelled it.
    pub root_ref: &'a str,
    /// Exact committed affected dependents, as the record holds them.
    pub dependent_refs: &'a [String],
    /// Terminal reason the origin was invalidated.
    pub invalidation_reason: Option<RevocationReason>,
    /// Terminal influence state.
    pub current_influence: InfluenceState,
    /// Fence/epoch the history that PRESENTED this closure was read under.
    ///
    /// This is the read-time coordinate, not the closure's commit epoch: the
    /// durable producer echoes its live dispatch fence and the consumer copies
    /// the echoed response fence, so both sides hash the same read. It binds
    /// the presentation to the read that served it and is deliberately kept
    /// separate from [`commit_state_fence`](Self::commit_state_fence), which
    /// binds the closure to the epoch it was committed at.
    pub state_fence: &'a StateFence,
    /// Fence/epoch the durable commit that produced this closure was committed
    /// under, read out of that commit's own recorded authority binding.
    ///
    /// This is the recorded coordinate. It is sourced from the immutable commit
    /// receipt the durable owner already holds, never from the serving read, so
    /// hashing it binds the closure identity to its commit epoch instead of to
    /// whichever read happened to project it.
    pub commit_state_fence: &'a StateFence,
    /// The closure's own committed revision.
    pub revision: u64,
    /// Declared traversal bounds the membership was proven under.
    pub bounds: RevocationClosureDigestBounds,
    /// Declared completeness, as one canonical [`REVOCATION_DISPOSITION_COMPLETE`]
    /// spelling.
    pub disposition: &'a str,
    /// References the committed membership declares it omitted.
    pub omissions: &'a [String],
    /// Declared count of the committed affected membership.
    pub affected_member_count: u64,
    /// Declared canonical digest of the committed affected membership.
    pub affected_member_digest: &'a str,
}

/// The one definition of a committed affected membership: the declared
/// origin reference plus every declared dependent, deduplicated.
///
/// The durable producer computes the digest/count coordinates over this set,
/// and recovery recomputes them over the presented set with the same
/// function, so the two can never describe different memberships.
#[must_use]
pub fn revocation_affected_members(
    origin_ref: &str,
    dependent_refs: &[String],
) -> BTreeSet<String> {
    let mut affected = BTreeSet::new();
    affected.insert(origin_ref.to_owned());
    affected.extend(dependent_refs.iter().cloned());
    affected
}

/// Canonical digest of one exact committed affected membership.
///
/// The preimage is the sorted membership. An unserializable membership has
/// no digest and is never given a defaulted one.
#[must_use]
pub fn revocation_affected_members_digest(affected: &BTreeSet<String>) -> Option<String> {
    let members: Vec<&str> = affected.iter().map(String::as_str).collect();
    let bytes = canonical_json_bytes(&RevocationAffectedMembersPreimage {
        affected_members: &members,
    })
    .ok()?;
    Some(sha256_hex(&bytes))
}

/// Canonical request hash of one exact closure presentation: evidence
/// version, closure identity, owner namespace, origin, sorted dependents,
/// reason, terminal state, the presenting read's fence, the recorded commit
/// fence/epoch, revision, bounds, disposition, sorted omissions, and the
/// affected-member count and digest.
///
/// I5.27 defines idempotency over canonical bytes, so a presentation whose
/// declared hash disagrees with its own bytes is an identity conflict
/// rather than a new operation. An unserializable presentation has no hash
/// and is never given a defaulted one.
#[must_use]
pub fn revocation_closure_canonical_digest(
    input: &RevocationClosureDigestInput<'_>,
) -> Option<String> {
    let mut dependents: Vec<&str> = input.dependent_refs.iter().map(String::as_str).collect();
    dependents.sort_unstable();
    let mut omissions: Vec<&str> = input.omissions.iter().map(String::as_str).collect();
    omissions.sort_unstable();
    let bytes = canonical_json_bytes(&RevocationClosureCanonicalPreimage {
        evidence_version: input.evidence_version,
        closure_id: input.closure_id,
        owner_namespace: input.owner_namespace,
        root_ref: input.root_ref,
        dependent_refs: dependents,
        invalidation_reason: input.invalidation_reason,
        current_influence: input.current_influence,
        state_fence: input.state_fence,
        commit_state_fence: input.commit_state_fence,
        revision: input.revision,
        bounds: input.bounds,
        disposition: input.disposition,
        omissions,
        affected_member_count: input.affected_member_count,
        affected_member_digest: input.affected_member_digest,
    })
    .ok()?;
    Some(sha256_hex(&bytes))
}

/// Canonical preimage of one committed affected membership.
/// Private on purpose: it is the digest input, not a wire contract.
#[derive(Serialize)]
struct RevocationAffectedMembersPreimage<'a> {
    affected_members: &'a [&'a str],
}

/// Canonical preimage of one exact revocation-closure presentation.
/// Private on purpose: it is the digest input, not a wire contract.
///
/// Dependent and omission order is spelling, not content (the digest sorts
/// both); every other presented coordinate is committed content under I5.27.
#[derive(Serialize)]
struct RevocationClosureCanonicalPreimage<'a> {
    evidence_version: u16,
    closure_id: &'a str,
    owner_namespace: &'a str,
    root_ref: &'a str,
    dependent_refs: Vec<&'a str>,
    invalidation_reason: Option<RevocationReason>,
    current_influence: InfluenceState,
    state_fence: &'a StateFence,
    commit_state_fence: &'a StateFence,
    revision: u64,
    bounds: RevocationClosureDigestBounds,
    disposition: &'a str,
    omissions: Vec<&'a str>,
    affected_member_count: u64,
    affected_member_digest: &'a str,
}
