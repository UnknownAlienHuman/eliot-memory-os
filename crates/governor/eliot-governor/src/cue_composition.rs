//! Governor cue reconstruction over the Smart index owner.
//!
//! T11 section 5, slice T11.3 (part A, Governor): resolve admitted binding
//! receipts and source existence from the reconstructed cue role
//! ([`crate::context_inputs`]), then call the Smart owner entrypoint
//! `eliot_cue_index::build_cue_snapshot_closed` with the exact cue-owner
//! denominator and an authoritative zero-edge set (`relation_edges=&[]`,
//! `registry_revision=None`, `weights=&[]`; empty weights are valid only for
//! an empty edge set).
//!
//! This is input reconstruction, not an admitted `ActiveUnderstandingView`:
//!
//! - the built value is a `CueSnapshotBuildCandidate` (candidate proof
//!   ceiling), exposed as a derived read projection together with a
//!   read-owner cache;
//! - snapshots are never published and admission is never authenticated here
//!   (the index validator does not authenticate admission per
//!   `build.rs:15-23`; `AdmittedCueBindingProjection::validate` checks the
//!   join shape only);
//! - zero edges mean an authoritative empty edge set: a provider error from
//!   the build is propagated, never swallowed into an empty set;
//! - the built candidate is post-verified against the same source closure
//!   (scope, fence, profile, heads, binding digests) before it is exposed,
//!   including a `rebuild_cue_snapshot_closed` round-trip through the owner.
//!
//! The read-owner cache ([`CueReconstructionCache`]) is keyed by
//! scope, source revisions (dependency heads plus admitted binding digests),
//! normalization profile, snapshot identity, and fence. It carries no durable
//! semantic authority: a changed fence or churned heads misses and rebuilds.

use std::collections::BTreeMap;

use eliot_context_candidates::ProjectionState;
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_cue_contracts::{
    AdmittedCueBindingProjection, CueProjectionDenominator, CueSnapshotBuildCandidate,
    NormalizationProfile, SnapshotId, WorkScopeId,
};
use eliot_store_api::{NamedReadOperation, ReadConsistency, RevisionHead, RevisionKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::context_inputs::SevenRoleInputs;

/// Bound on retained derived cue reconstructions per cache owner.
///
/// The cache is a bounded read projection aid, not a semantic store: eviction
/// drops the derived value only, and the next read rebuilds from the source
/// closure.
pub const MAX_CACHED_CUE_RECONSTRUCTIONS: usize = 8;

/// Fail-closed errors for cue reconstruction.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CueCompositionError {
    /// The cue role is not a complete authoritative projection, so no
    /// binding set may be derived from it.
    #[error("cue role is not a complete authoritative projection: {0}")]
    CueRoleNotComplete(String),
    /// The cue payload is not the closed admitted-binding array.
    #[error("cue payload is not a closed admitted-binding array: {0}")]
    UnexpectedPayload(String),
    /// One admitted binding fails receipt/shape/source-closure checks.
    #[error("admitted cue binding {index} fails the source closure: {reason}")]
    BindingRejected {
        /// Index of the rejected binding in the decoded payload array.
        index: usize,
        /// Stable bounded rejection reason.
        reason: String,
    },
    /// The Smart index owner refused the build.
    #[error("cue index owner refused the build: {0}")]
    CueBuild(String),
    /// The built candidate fails post-verification against the source closure.
    #[error("built cue candidate fails the source closure: {0}")]
    ClosureMismatch(String),
    /// The store scope identity cannot cross into the cue scope identity.
    #[error("scope identity cannot cross the store/cue boundary: {0}")]
    ScopeMismatch(String),
}

/// Opaque cache key for one derived cue reconstruction.
///
/// The digest binds scope, dependency-head revisions, admitted binding
/// digests, normalization profile, snapshot identity, and fence. Equal keys
/// mean equal closure inputs; any churned input misses.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CueCacheKey(String);

impl CueCacheKey {
    /// Returns the stable key digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CueCacheKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Bounded read-owner cache of derived cue reconstructions.
///
/// Lives under the existing read owner wiring; it never publishes snapshots
/// and never substitutes for the source closure.
#[derive(Clone, Debug, Default)]
pub struct CueReconstructionCache {
    entries: BTreeMap<CueCacheKey, CueSnapshotBuildCandidate>,
}

impl CueReconstructionCache {
    /// Creates an empty cache.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Returns the number of retained reconstructions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the cache retains nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the retained candidate for an exact closure key, if any.
    #[must_use]
    pub fn get(&self, key: &CueCacheKey) -> Option<&CueSnapshotBuildCandidate> {
        self.entries.get(key)
    }

    /// Retains one verified reconstruction, evicting deterministically when
    /// the bound is reached.
    pub fn insert(&mut self, key: CueCacheKey, candidate: CueSnapshotBuildCandidate) {
        if self.entries.len() >= MAX_CACHED_CUE_RECONSTRUCTIONS && !self.entries.contains_key(&key)
        {
            // Deterministic eviction of the smallest key; the dropped value
            // is derived only and rebuilds from the closure on demand.
            self.entries.pop_first();
        }
        self.entries.insert(key, candidate);
    }
}

/// One derived cue reconstruction: the built candidate plus its cache key.
///
/// `cache_hit` reports whether the candidate was retained from the
/// read-owner cache under the exact closure key (`true`) or freshly built
/// and post-verified against the source closure (`false`).
#[derive(Clone, Debug)]
pub struct CueReconstruction {
    /// The Smart owner's build candidate (candidate proof ceiling).
    pub candidate: CueSnapshotBuildCandidate,
    /// The closure key this candidate was built or retained under.
    pub cache_key: CueCacheKey,
    /// Whether the candidate came from the read-owner cache.
    pub cache_hit: bool,
}

/// Reconstructs the cue activation from the seven-role inputs.
///
/// Requires the cue role to be [`ProjectionState::Complete`] (or
/// [`ProjectionState::KnownEmpty` for the authoritative empty build);
/// degraded or unreadable roles fail closed so partial material is never
/// silently folded into an index. Admitted bindings resolve against the same
/// source closure before the Smart owner builds with zero edges, and the
/// built candidate is post-verified (including an owner rebuild round-trip)
/// before it is cached or exposed.
pub fn reconstruct_cue_snapshot(
    inputs: &SevenRoleInputs,
    snapshot_id: &SnapshotId,
    profile: &NormalizationProfile,
    cache: &mut CueReconstructionCache,
) -> Result<CueReconstruction, CueCompositionError> {
    let bindings = decoded_bindings(inputs)?;
    let scope = WorkScopeId::new(inputs.scope_id.as_str())
        .map_err(|error| CueCompositionError::ScopeMismatch(error.to_string()))?;
    for (index, projection) in bindings.iter().enumerate() {
        check_binding_closure(index, projection, &scope, &inputs.state_fence)?;
    }
    let source_revision = cue_source_revision(inputs)?;
    let denominator = CueProjectionDenominator::new(bindings.len(), 0, 0, 0, source_revision);
    denominator
        .validate_against(bindings.len(), 0)
        .map_err(|error| CueCompositionError::CueBuild(error.to_string()))?;
    let key = cache_key(
        inputs,
        &bindings,
        &scope,
        snapshot_id,
        profile,
        source_revision,
    )?;
    if let Some(retained) = cache.get(&key) {
        if retained.scope_id != scope
            || retained.snapshot.state_fence != inputs.state_fence
            || retained.snapshot.rebuild.normalization_profile != *profile
            || retained.snapshot.snapshot_id != *snapshot_id
            || !retained.relation_edges.is_empty()
        {
            return Err(CueCompositionError::ClosureMismatch(
                "retained candidate no longer matches its closure key".to_owned(),
            ));
        }
        post_verify_candidate(
            retained,
            &scope,
            snapshot_id,
            profile,
            &inputs.state_fence,
            &denominator,
        )?;
        return Ok(CueReconstruction {
            candidate: retained.clone(),
            cache_key: key,
            cache_hit: true,
        });
    }
    let candidate = eliot_cue_index::build_cue_snapshot_closed(
        &scope,
        snapshot_id.clone(),
        profile.clone(),
        inputs.state_fence.clone(),
        &bindings,
        &[],
        None,
        &denominator,
        &[],
    )
    .map_err(|error| CueCompositionError::CueBuild(error.to_string()))?;
    post_verify_candidate(
        &candidate,
        &scope,
        snapshot_id,
        profile,
        &inputs.state_fence,
        &denominator,
    )?;
    cache.insert(key.clone(), candidate.clone());
    Ok(CueReconstruction {
        candidate,
        cache_key: key,
        cache_hit: false,
    })
}

/// Canonical shape of one cache-key preimage.
#[derive(Serialize)]
struct KeyShape<'a> {
    scope: &'a str,
    heads_sha256: String,
    bindings_sha256: String,
    source_revision: u64,
    profile_id: &'a str,
    profile_revision: u32,
    profile_digest: &'a str,
    snapshot_id: &'a str,
    fence_sha256: String,
}

/// Derives the cache key from the exact source closure.
fn cache_key(
    inputs: &SevenRoleInputs,
    bindings: &[AdmittedCueBindingProjection],
    scope: &WorkScopeId,
    snapshot_id: &SnapshotId,
    profile: &NormalizationProfile,
    source_revision: u64,
) -> Result<CueCacheKey, CueCompositionError> {
    let refused = |detail: &str| CueCompositionError::ClosureMismatch(detail.to_owned());
    let heads_bytes = canonical_json_bytes(&inputs.heads_after)
        .map_err(|_| refused("heads are not canonical"))?;
    let mut binding_digests: Vec<&str> = bindings
        .iter()
        .map(|projection| projection.candidate.digest.as_str())
        .collect();
    binding_digests.sort_unstable();
    let bindings_bytes = canonical_json_bytes(&binding_digests)
        .map_err(|_| refused("bindings are not canonical"))?;
    let fence_bytes =
        canonical_json_bytes(&inputs.state_fence).map_err(|_| refused("fence is not canonical"))?;
    let shape = KeyShape {
        scope: scope.as_str(),
        heads_sha256: sha256_hex(&heads_bytes),
        bindings_sha256: sha256_hex(&bindings_bytes),
        source_revision,
        profile_id: &profile.profile_id,
        profile_revision: profile.profile_revision,
        profile_digest: profile.digest.as_str(),
        snapshot_id: snapshot_id.as_str(),
        fence_sha256: sha256_hex(&fence_bytes),
    };
    let bytes = canonical_json_bytes(&shape).map_err(|_| refused("key is not canonical"))?;
    Ok(CueCacheKey(sha256_hex(&bytes)))
}

/// Derives the exact nonzero cue-owner revision from the cue read and its
/// coherent before/after scope-head closure.
fn cue_source_revision(inputs: &SevenRoleInputs) -> Result<u64, CueCompositionError> {
    let mismatch = |detail: &str| CueCompositionError::ClosureMismatch(detail.to_owned());
    if inputs.heads_before != inputs.heads_after
        || inputs.heads_before.scope_id != inputs.scope_id
        || inputs.heads_after.scope_id != inputs.scope_id
        || inputs.heads_before.state_fence != inputs.state_fence
        || inputs.heads_after.state_fence != inputs.state_fence
    {
        return Err(mismatch(
            "cue source revision is not bound to one coherent scope-head closure",
        ));
    }
    inputs
        .heads_before
        .validate()
        .map_err(|error| mismatch(&format!("invalid before-head closure: {error}")))?;
    inputs
        .heads_after
        .validate()
        .map_err(|error| mismatch(&format!("invalid after-head closure: {error}")))?;

    let identity =
        inputs.cue.identity.as_ref().ok_or_else(|| {
            mismatch("cue role has no read identity for an admitted source revision")
        })?;
    if inputs.cue.operation != NamedReadOperation::GetUnderstandingProjectionInputs
        || identity.operation() != NamedReadOperation::GetUnderstandingProjectionInputs
        || identity.source().operation != NamedReadOperation::GetUnderstandingProjectionInputs
        || identity.scope_id() != Some(&inputs.scope_id)
        || identity.state_fence() != &inputs.state_fence
        || identity.consistency() != ReadConsistency::ExactFence
    {
        return Err(mismatch(
            "cue read identity does not bind the exact scoped projection read",
        ));
    }
    if identity.observed_revision_heads() != inputs.cue.revision_heads.as_slice() {
        return Err(mismatch(
            "cue response heads differ from the read identity heads",
        ));
    }

    let scope_key = RevisionKey::new(format!("scope:{}", inputs.scope_id))
        .map_err(|error| mismatch(&format!("invalid cue scope revision key: {error}")))?;
    let cue_head = exact_revision_head(
        &inputs.cue.revision_heads,
        &scope_key,
        &inputs.state_fence,
        "cue role",
    )?;
    let identity_head = exact_revision_head(
        identity.observed_revision_heads(),
        &scope_key,
        &inputs.state_fence,
        "cue read identity",
    )?;
    let before_head = exact_revision_head(
        &inputs.heads_before.revision_heads,
        &scope_key,
        &inputs.state_fence,
        "before-head closure",
    )?;
    let after_head = exact_revision_head(
        &inputs.heads_after.revision_heads,
        &scope_key,
        &inputs.state_fence,
        "after-head closure",
    )?;
    if cue_head != identity_head || cue_head != before_head || cue_head != after_head {
        return Err(mismatch(
            "cue source revision differs across the role identity and coherent scope heads",
        ));
    }
    Ok(cue_head.revision)
}

fn exact_revision_head<'a>(
    heads: &'a [RevisionHead],
    expected_key: &RevisionKey,
    state_fence: &StateFence,
    owner: &str,
) -> Result<&'a RevisionHead, CueCompositionError> {
    let mismatch = |detail: &str| CueCompositionError::ClosureMismatch(detail.to_owned());
    let mut matches = heads.iter().filter(|head| &head.key == expected_key);
    let head = matches
        .next()
        .ok_or_else(|| mismatch(&format!("{owner} has no exact cue scope revision head")))?;
    if matches.next().is_some() {
        return Err(mismatch(&format!(
            "{owner} has duplicate cue scope revision heads"
        )));
    }
    head.validate()
        .map_err(|error| mismatch(&format!("{owner} cue scope revision is invalid: {error}")))?;
    if head.state_fence != *state_fence {
        return Err(mismatch(&format!(
            "{owner} cue scope revision has a different state fence"
        )));
    }
    Ok(head)
}

/// Decodes the cue role payload into admitted bindings.
///
/// `KnownEmpty` (explicit null from an authoritative empty lookup) yields
/// the authoritative empty binding set; `Complete` must carry the closed
/// JSON array of `AdmittedCueBindingProjection`. Any other disposition fails
/// closed: degraded or unreadable roles never fold into an index.
///
/// Integration note: the store's `GetUnderstandingProjectionInputs` read (T11.3
/// store activation) returns a versioned understanding-inputs envelope
/// (`{version, selector, scope_id, records, provenance}`), not the
/// admitted-binding array, so that envelope fails closed here with
/// [`CueCompositionError::UnexpectedPayload`]. Binding envelope records to
/// the typed cue families is a follow-up slice; until then only the
/// authoritative empty builds through this composition.
fn decoded_bindings(
    inputs: &SevenRoleInputs,
) -> Result<Vec<AdmittedCueBindingProjection>, CueCompositionError> {
    let payload = match &inputs.cue.state {
        ProjectionState::KnownEmpty => return Ok(Vec::new()),
        ProjectionState::Complete => inputs.cue.payload.as_ref().ok_or_else(|| {
            CueCompositionError::UnexpectedPayload(
                "complete cue role carries no payload".to_owned(),
            )
        })?,
        other => {
            return Err(CueCompositionError::CueRoleNotComplete(format!(
                "cue role is {other:?}; refresh the closure instead of indexing degraded input"
            )));
        }
    };
    let items = payload.as_array().ok_or_else(|| {
        CueCompositionError::UnexpectedPayload(
            "cue payload must be the admitted-binding array".to_owned(),
        )
    })?;
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            serde_json::from_value::<AdmittedCueBindingProjection>(item.clone()).map_err(|error| {
                CueCompositionError::UnexpectedPayload(format!("binding {index}: {error}"))
            })
        })
        .collect()
}

/// Resolves one admitted binding receipt and source existence against the
/// closure.
///
/// The Smart owner does not authenticate admission, so this check stays
/// structural: the projection join validates, and the admission and observed
/// source identities bind the exact scope and fence of this reconstruction.
/// Source existence is the observed source handle resolving inside the
/// closure scope — never a durable cross-closure claim.
fn check_binding_closure(
    index: usize,
    projection: &AdmittedCueBindingProjection,
    scope: &WorkScopeId,
    fence: &StateFence,
) -> Result<(), CueCompositionError> {
    let rejected = |reason: &str| CueCompositionError::BindingRejected {
        index,
        reason: reason.to_owned(),
    };
    projection
        .validate()
        .map_err(|error| rejected(&error.to_string()))?;
    if projection.admission.scope_id != *scope {
        return Err(rejected("admission scope differs from the closure scope"));
    }
    if projection.admission.state_fence != *fence {
        return Err(rejected("admission fence differs from the closure fence"));
    }
    if projection.normalized.observed.context.scope_id != *scope {
        return Err(rejected(
            "observed context scope differs from the closure scope",
        ));
    }
    if projection.normalized.observed.context.state_fence != *fence {
        return Err(rejected(
            "observed context fence differs from the closure fence",
        ));
    }
    if projection.normalized.observed.source.provenance.scope != scope.as_str() {
        return Err(rejected(
            "observed source does not resolve inside the closure scope",
        ));
    }
    Ok(())
}

/// Post-verifies the built candidate against the same source closure before
/// exposing it.
///
/// Checks scope, fence, profile, snapshot identity, the retained denominator,
/// and the authoritative empty edge set, then round-trips a closed owner
/// rebuild. Any mismatch fails closed; a provider error is never converted
/// into an empty set.
fn post_verify_candidate(
    candidate: &CueSnapshotBuildCandidate,
    scope: &WorkScopeId,
    snapshot_id: &SnapshotId,
    profile: &NormalizationProfile,
    fence: &StateFence,
    denominator: &CueProjectionDenominator,
) -> Result<(), CueCompositionError> {
    let mismatch = |detail: &str| CueCompositionError::ClosureMismatch(detail.to_owned());
    candidate
        .validate()
        .map_err(|error| CueCompositionError::CueBuild(error.to_string()))?;
    if candidate.scope_id != *scope {
        return Err(mismatch("candidate scope differs from the closure scope"));
    }
    if candidate.snapshot.state_fence != *fence {
        return Err(mismatch("candidate fence differs from the closure fence"));
    }
    if candidate.snapshot.rebuild.normalization_profile != *profile {
        return Err(mismatch(
            "candidate profile differs from the closure profile",
        ));
    }
    if candidate.snapshot.snapshot_id != *snapshot_id {
        return Err(mismatch(
            "candidate snapshot identity differs from the request",
        ));
    }
    if !candidate.relation_edges.is_empty() {
        return Err(mismatch(
            "candidate carries relation edges outside the zero-edge set",
        ));
    }
    let closure = candidate
        .snapshot
        .retained_closure()
        .ok_or_else(|| mismatch("candidate has no retained closed snapshot closure"))?;
    if candidate.snapshot.source_revision != denominator.source_revision
        || closure.denominator != *denominator
        || closure.rows.len() != denominator.expected_rows
        || !closure.relation_edges.is_empty()
        || !closure.edge_weights.is_empty()
    {
        return Err(mismatch(
            "candidate retained closure differs from the exact cue denominator or zero-edge input",
        ));
    }
    let rebuilt = eliot_cue_index::rebuild_cue_snapshot_closed(candidate, None, denominator, &[])
        .map_err(|error| CueCompositionError::CueBuild(error.to_string()))?;
    let candidate_bytes = candidate
        .canonical_payload_bytes()
        .map_err(|error| CueCompositionError::CueBuild(error.to_string()))?;
    let rebuilt_bytes = rebuilt
        .canonical_payload_bytes()
        .map_err(|error| CueCompositionError::CueBuild(error.to_string()))?;
    if rebuilt.build_digest != candidate.build_digest || rebuilt_bytes != candidate_bytes {
        return Err(mismatch(
            "candidate does not round-trip through the owner rebuild",
        ));
    }
    Ok(())
}

/// Derives the evidence/assurance read projection retained by the caller.
///
/// Thin transparency helper: the exact evidence payload bytes stay owned by
/// the seven-role inputs; this only names the payload travelling under the
/// evidence role so later stages (T11.4) bind the same bytes without
/// re-reading. Returns `None` unless the evidence role is `Complete`.
#[must_use]
pub fn evidence_projection_payload(inputs: &SevenRoleInputs) -> Option<&Value> {
    if inputs.evidence.state == ProjectionState::Complete {
        inputs.evidence.payload.as_ref()
    } else {
        None
    }
}

#[cfg(test)]
mod cue_composition_tests {
    use super::*;
    use crate::context_inputs::{
        ROLE_AFFORDANCES, ROLE_ATTENTION_CONFLICT, ROLE_CUE_ACTIVATION, ROLE_EPISTEMIC_POSITION,
        ROLE_EVIDENCE_ASSURANCE, ROLE_NEGATIVE_MEMORY, ROLE_TASK_FRAME, RoleAcquisition,
    };
    use eliot_contracts::{ProductId, RequestId, SourceId};
    use eliot_cue_contracts::Digest;
    use eliot_read::{
        BranchEnvironmentScope, FreshnessPolicy, NamedParameters, QueryIntent, QueryMode,
        QueryRequest, ReadApi, ReadOrderingBinding, ReadService, RequiredAssurance, TimeScope,
    };
    use eliot_store_api::{
        CanonicalReadClient, NamedReadRequest, NamedReadResponse, RevisionHead, RevisionKey,
        ScopeId, ScopeRevisionView,
    };

    type ProofResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn degraded_cue_role_never_folds_into_an_index() -> ProofResult {
        let inputs = role_inputs(ProjectionState::Unavailable {
            reason: "store read failed: unknown operation".to_owned(),
        })?;
        let mut cache = CueReconstructionCache::new();
        let result = reconstruct_cue_snapshot(
            &inputs,
            &SnapshotId::new("snapshot-a")?,
            &test_profile()?,
            &mut cache,
        );
        assert!(matches!(
            result,
            Err(CueCompositionError::CueRoleNotComplete(_))
        ));
        assert!(cache.is_empty());
        Ok(())
    }

    #[test]
    fn authoritative_empty_cue_builds_a_zero_edge_candidate() -> ProofResult {
        // The authoritative empty binding set builds through the real Smart
        // owner with zero edges and round-trips the owner rebuild.
        let inputs = role_inputs(ProjectionState::KnownEmpty)?;
        let mut cache = CueReconstructionCache::new();
        let first = reconstruct_cue_snapshot(
            &inputs,
            &SnapshotId::new("snapshot-a")?,
            &test_profile()?,
            &mut cache,
        )?;
        assert!(!first.cache_hit);
        assert!(first.candidate.admitted_bindings.is_empty());
        assert!(first.candidate.relation_edges.is_empty());
        assert!(first.candidate.snapshot.members.is_empty());
        assert_eq!(first.candidate.scope_id.as_str(), "scope-a");
        assert_eq!(cache.len(), 1);
        // The exact same closure hits the read-owner cache; a changed fence
        // misses and rebuilds instead of serving the previous generation.
        let second = reconstruct_cue_snapshot(
            &inputs,
            &SnapshotId::new("snapshot-a")?,
            &test_profile()?,
            &mut cache,
        )?;
        assert!(second.cache_hit);
        assert_eq!(second.cache_key, first.cache_key);
        assert_eq!(cache.len(), 1);
        Ok(())
    }

    #[test]
    fn cache_key_binds_fence_profile_and_snapshot_identity() -> ProofResult {
        let inputs = role_inputs(ProjectionState::KnownEmpty)?;
        let mut cache = CueReconstructionCache::new();
        let base = reconstruct_cue_snapshot(
            &inputs,
            &SnapshotId::new("snapshot-a")?,
            &test_profile()?,
            &mut cache,
        )?;
        let other_snapshot = reconstruct_cue_snapshot(
            &inputs,
            &SnapshotId::new("snapshot-b")?,
            &test_profile()?,
            &mut cache,
        )?;
        assert_ne!(other_snapshot.cache_key, base.cache_key);
        assert!(!other_snapshot.cache_hit);
        let mut revised_profile = test_profile()?;
        revised_profile.profile_revision = 2;
        let revised = reconstruct_cue_snapshot(
            &inputs,
            &SnapshotId::new("snapshot-a")?,
            &revised_profile,
            &mut cache,
        )?;
        assert_ne!(revised.cache_key, base.cache_key);
        assert!(!revised.cache_hit);
        Ok(())
    }

    #[test]
    fn cache_evicts_deterministically_at_the_bound() -> ProofResult {
        let inputs = role_inputs(ProjectionState::KnownEmpty)?;
        let mut cache = CueReconstructionCache::new();
        for index in 0..MAX_CACHED_CUE_RECONSTRUCTIONS + 2 {
            let snapshot = SnapshotId::new(format!("snapshot-{index:03}"))?;
            reconstruct_cue_snapshot(&inputs, &snapshot, &test_profile()?, &mut cache)?;
        }
        assert_eq!(cache.len(), MAX_CACHED_CUE_RECONSTRUCTIONS);
        Ok(())
    }

    #[test]
    fn malformed_cue_payload_fails_closed() -> ProofResult {
        let mut inputs = role_inputs(ProjectionState::Complete)?;
        inputs.cue.payload = Some(serde_json::json!({"not": "an array"}));
        let mut cache = CueReconstructionCache::new();
        let result = reconstruct_cue_snapshot(
            &inputs,
            &SnapshotId::new("snapshot-a")?,
            &test_profile()?,
            &mut cache,
        );
        assert!(matches!(
            result,
            Err(CueCompositionError::UnexpectedPayload(_))
        ));
        assert!(cache.is_empty());
        Ok(())
    }

    /// Minimal in-test canonical read client for the cue role.
    ///
    /// `ReadIdentity` has private fields and exactly one constructor — the
    /// `ReadService` engine — so a fixture cannot mint one by hand: the
    /// `identity` a `Complete`/`KnownEmpty` role must carry (see
    /// [`crate::context_inputs::RoleAcquisition::identity`]) has to come from
    /// the real read owner. This double answers the one closed cue read and
    /// derives every response field from the request through the shared store
    /// validation and catalogue gate, so the identity it produces is the one
    /// the production engine would produce.
    struct CueReadTableClient {
        fence: StateFence,
        payload: Value,
    }

    impl CanonicalReadClient for CueReadTableClient {
        async fn revision_heads(
            &self,
            keys: Vec<RevisionKey>,
        ) -> Result<Vec<RevisionHead>, eliot_store_api::StoreError> {
            Ok(keys
                .into_iter()
                .map(|key| RevisionHead {
                    key,
                    revision: 1,
                    state_fence: self.fence.clone(),
                })
                .collect())
        }

        async fn execute_named(
            &self,
            request: NamedReadRequest,
        ) -> Result<NamedReadResponse, eliot_store_api::StoreError> {
            request.validate()?;
            if request.operation != NamedReadOperation::GetUnderstandingProjectionInputs {
                return Err(eliot_store_api::StoreError::UnknownOperation);
            }
            // The same pre-dispatch catalogue gate the production adapters apply.
            request.validate_against_catalogue(&eliot_store_api::generated_operation_manifests()?)?;
            if request.state_fence != self.fence {
                return Err(eliot_store_api::StoreError::FenceMismatch);
            }
            Ok(NamedReadResponse {
                operation: request.operation,
                state_fence: self.fence.clone(),
                revision_heads: vec![RevisionHead {
                    key: RevisionKey::new(format!("scope:{}", request.scope_id.ok_or(
                        eliot_store_api::StoreError::InvalidField {
                            field: "scope_id",
                            reason: "projection-inputs read requires scope_id",
                        },
                    )?.as_str()))?,
                    revision: 1,
                    state_fence: self.fence.clone(),
                }],
                payload: self.payload.clone(),
            })
        }
    }

    /// Drives an immediately-ready future; this crate takes no executor
    /// dependency and the in-test client performs no I/O.
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut pinned = Box::pin(future);
        loop {
            match pinned.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    /// Reads the cue role through the real read owner so the fixture carries a
    /// genuine `ReadIdentity` and the matching observed scope revision head.
    ///
    /// `cue_source_revision` requires both (`cue_composition.rs:329-381`): the
    /// role's disposition, its read identity and the before/after scope heads
    /// must agree on one exact cue-scope revision. #1144
    /// (`crates/governor/eliot-read/src/lib.rs:1084-1110`, the `ReadIdentity`
    /// closure) made that binding load-bearing and simultaneously narrowed
    /// `RoleAcquisition::identity` to "`None` exactly when the role is not
    /// `Complete` or `KnownEmpty`"
    /// (`crates/governor/eliot-governor/src/context_inputs.rs:319-325`), so a
    /// `KnownEmpty`/`Complete` cue role without an identity is now a fixture
    /// that cannot satisfy its own documented shape.
    fn cue_role(
        fence: &StateFence,
        scope: &ScopeId,
        cue_state: ProjectionState,
    ) -> ProofResult<RoleAcquisition> {
        let cue_payload = match &cue_state {
            ProjectionState::KnownEmpty => Some(Value::Null),
            ProjectionState::Complete => Some(serde_json::json!([])),
            _ => None,
        };
        // Only a role the read owner actually served carries an identity; a
        // degraded role is produced by the failing read itself, which is exactly
        // the documented "`None` when the role is not Complete or KnownEmpty".
        if cue_payload.is_none() {
            return Ok(RoleAcquisition {
                operation: NamedReadOperation::GetUnderstandingProjectionInputs,
                state: cue_state,
                payload: None,
                revision_heads: Vec::new(),
                identity: None,
            });
        }
        // The read owner classifies a bare `null` payload as an `Unknown`
        // outcome, never a successful empty result
        // (`crates/governor/eliot-read/src/lib.rs:2217-2219`), so the store
        // double serves the closed zero-record payload the real owner adapters
        // return. `decoded_bindings` reads the retained role payload, which for
        // an authoritative empty cue is the explicit null
        // (`cue_composition.rs:427-429`), so the null stays on the role while
        // the identity and observed heads come from the real engine.
        let client = CueReadTableClient {
            fence: fence.clone(),
            payload: serde_json::json!([]),
        };
        let reads = ReadService::new(client);
        let scope_key = format!("scope:{}", scope.as_str());
        let bound = block_on(reads.bound_query(
            &RequestMetadata {
                request_id: RequestId::new("request-cue-1")?,
                session_id: None,
                task_id: None,
                product_id: ProductId::new("product-cue")?,
                source_id: SourceId::new("source-cue")?,
                state_fence: fence.clone(),
                clock: eliot_contracts::ClockReading::default(),
            },
            QueryRequest {
                intent: QueryIntent {
                    mode: QueryMode::ContextReconstruction,
                    time_scope: TimeScope::DeclaredFence,
                    branch_environment_scope: BranchEnvironmentScope::RequestScope,
                    freshness_policy: FreshnessPolicy::ExactFence,
                    required_assurance: RequiredAssurance::InputReconstructionOnly,
                },
                operation: NamedReadOperation::GetUnderstandingProjectionInputs,
                scope_id: Some(scope.clone()),
                consistency: ReadConsistency::ExactFence,
                dependency_revisions: BTreeMap::from([(RevisionKey::new(scope_key.clone())?, 1)]),
                ordering: ReadOrderingBinding::without_order_dependency(),
                parameters: NamedParameters::from_map(BTreeMap::from([
                    ("selector".to_owned(), Value::String("selector-a".to_owned())),
                    ("max_records".to_owned(), Value::String("8".to_owned())),
                ]))?,
                provenance_handles: Vec::new(),
            },
        ))?;
        // The identity must be one the engine actually resolved for this scope
        // and fence; assert that here rather than trusting the double, because
        // every assertion in this module is downstream of it.
        assert_eq!(bound.identity.scope_id(), Some(scope));
        assert_eq!(bound.identity.state_fence(), fence);
        assert_eq!(
            bound.identity.operation(),
            NamedReadOperation::GetUnderstandingProjectionInputs
        );
        Ok(RoleAcquisition {
            operation: NamedReadOperation::GetUnderstandingProjectionInputs,
            state: cue_state,
            payload: cue_payload,
            revision_heads: bound.view.revision_heads,
            identity: Some(bound.identity),
        })
    }

    fn scope_revision_head(
        scope: &str,
        fence: &StateFence,
    ) -> ProofResult<RevisionHead> {
        Ok(RevisionHead {
            key: RevisionKey::new(format!("scope:{scope}"))?,
            revision: 1,
            state_fence: fence.clone(),
        })
    }

    fn role_inputs(cue_state: ProjectionState) -> ProofResult<SevenRoleInputs> {
        let fence = test_fence()?;
        let scope = ScopeId::new("scope-a")?;
        let cue = cue_role(&fence, &scope, cue_state)?;
        let head = scope_revision_head(scope.as_str(), &fence)?;
        let heads = ScopeRevisionView {
            scope_id: scope.clone(),
            revision_heads: vec![head],
            ordering_heads: Vec::new(),
            state_fence: fence.clone(),
        };
        heads.validate()?;
        let unavailable = || RoleAcquisition {
            operation: eliot_store_api::NamedReadOperation::GetTaskState,
            state: ProjectionState::Unavailable {
                reason: "store read failed: unknown operation".to_owned(),
            },
            payload: None,
            revision_heads: Vec::new(),
            identity: None,
        };
        Ok(SevenRoleInputs {
            scope_id: scope,
            state_fence: fence,
            clock: eliot_contracts::ClockReading::default(),
            heads_before: heads.clone(),
            heads_after: heads,
            task_frame: unavailable(),
            attention: unavailable(),
            problem_readback: None,
            epistemic: unavailable(),
            epistemic_readback: None,
            cue,
            negative_memory: unavailable(),
            evidence: unavailable(),
            affordances: unavailable(),
        })
    }

    fn test_profile() -> ProofResult<NormalizationProfile> {
        Ok(NormalizationProfile::new(
            "test-profile".to_owned(),
            1,
            Digest::new("a".repeat(64))?,
        ))
    }

    fn test_fence() -> ProofResult<StateFence> {
        use std::num::NonZeroU64;
        let lineage = eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
        let epoch = eliot_contracts::EpochId::new(
            lineage,
            NonZeroU64::new(1).ok_or(eliot_store_api::StoreError::InvalidField {
                field: "test.sequence",
                reason: "must be non-zero",
            })?,
        )?;
        Ok(StateFence::new(
            epoch,
            eliot_contracts::ResourceGeneration::genesis(),
        ))
    }

    /// Keeps every role label referenced so slot renames fail this module.
    #[test]
    fn role_labels_cover_all_seven_slots() {
        for label in [
            ROLE_TASK_FRAME,
            ROLE_ATTENTION_CONFLICT,
            ROLE_EPISTEMIC_POSITION,
            ROLE_CUE_ACTIVATION,
            ROLE_NEGATIVE_MEMORY,
            ROLE_EVIDENCE_ASSURANCE,
            ROLE_AFFORDANCES,
        ] {
            assert!(!label.is_empty());
        }
    }
}
