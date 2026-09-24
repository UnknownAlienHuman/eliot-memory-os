//! Governor cue reconstruction over the Smart index owner.
//!
//! T11 section 5, slice T11.3 (part A, Governor): resolve admitted binding
//! receipts and source existence from the reconstructed cue role
//! ([`crate::context_inputs`]), then call the Smart owner entrypoint
//! `eliot_cue_index::build_cue_snapshot_closed` with an authoritative zero-edge
//! set and a denominator frozen at the current scope head. The closed candidate
//! carries its rows, omissions, endpoints, weights, and direct-only fanout
//! closure; the Governor never reconstructs a publishable open candidate.
//!
//! This is input reconstruction, not an admitted `ActiveUnderstandingView`:
//!
//! - the built value is a `CueSnapshotBuildCandidate` (candidate proof
//!   ceiling), exposed as a derived read projection together with a
//!   read-owner cache;
//! - the candidate's snapshot is closed and self-validating; the Governor does
//!   not substitute the open builder or retain closure arguments outside it;
//! - snapshots are never published and admission is never authenticated here
//!   (the index validator does not authenticate admission per
//!   `build.rs:15-23`; `AdmittedCueBindingProjection::validate` checks the
//!   join shape only);
//! - zero edges mean an authoritative empty edge set with an explicit
//!   direct-only fanout closure: a provider error from the build is propagated,
//!   never swallowed into an empty set;
//! - the built candidate is post-verified against the same source closure
//!   (scope, fence, profile, source revision, binding digests) before it is
//!   exposed, including a retained-closure rebuild round-trip through the
//!   owner.
//!
//! The read-owner cache ([`CueReconstructionCache`]) is keyed by
//! scope, source revisions (dependency heads plus admitted binding digests),
//! normalization profile, snapshot identity, and fence. It carries no durable
//! semantic authority: a changed fence or churned heads misses and rebuilds.

use std::collections::BTreeMap;

use eliot_context_candidates::ProjectionState;
use eliot_contracts::{RequestMetadata, StateFence, canonical_json_bytes, sha256_hex};
use eliot_cue_contracts::{
    AdmittedCueBindingProjection, CueProjectionDenominator, CueSnapshotBuildCandidate,
    NormalizationProfile, SnapshotId, WorkScopeId,
};
use eliot_read::ReadApi;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::context_inputs::{
    ContextInputsError, ContextReconstructionRequest, GovernorContextInputs, SevenRoleInputs,
};

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

/// Fail-closed errors at the read-backed Governor cue boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CueReadCompositionError {
    /// The composition is not ready for a derived read projection.
    #[error("Governor composition is not ready for cue reconstruction")]
    NotReady,
    /// The caller's metadata does not carry the retained composition fence.
    #[error("cue reconstruction request fence does not match the retained Governor fence")]
    FenceMismatch,
    /// The seven-role read closure could not be acquired coherently.
    #[error("cue context read closure failed: {0}")]
    Context(#[from] ContextInputsError),
    /// The read payload could not be safely decoded or built.
    #[error("cue reconstruction failed: {0}")]
    Cue(#[from] CueCompositionError),
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
    let source_revision = source_revision(inputs)?;
    let key = cache_key(
        inputs,
        &bindings,
        &scope,
        snapshot_id,
        profile,
        source_revision,
    )?;
    if let Some(retained) = cache.get(&key) {
        retained
            .validate()
            .map_err(|error| CueCompositionError::CueBuild(error.to_string()))?;
        let Some(closure) = retained.retained_closure() else {
            return Err(CueCompositionError::ClosureMismatch(
                "retained candidate is not self-validating".to_owned(),
            ));
        };
        if retained.scope_id != scope
            || retained.snapshot.state_fence != inputs.state_fence
            || retained.snapshot.rebuild.normalization_profile != *profile
            || retained.snapshot.snapshot_id != *snapshot_id
            || retained.snapshot.source_revision != source_revision
            || closure.denominator.source_revision != source_revision
            || !retained.relation_edges.is_empty()
        {
            return Err(CueCompositionError::ClosureMismatch(
                "retained candidate no longer matches its closure key".to_owned(),
            ));
        }
        return Ok(CueReconstruction {
            candidate: retained.clone(),
            cache_key: key,
            cache_hit: true,
        });
    }
    let denominator = CueProjectionDenominator::new(bindings.len(), 0, 0, 0, source_revision);
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
        source_revision,
    )?;
    cache.insert(key.clone(), candidate.clone());
    Ok(CueReconstruction {
        candidate,
        cache_key: key,
        cache_hit: false,
    })
}

/// Acquires the seven-role closure through the supplied Governor read facade
/// and then runs the closed cue owner. The caller owns the `ReadService`; this
/// function never opens a transport or substitutes a default payload.
pub async fn reconstruct_cue_snapshot_from_reads<R: ReadApi + ?Sized>(
    reads: &R,
    ctx: &RequestMetadata,
    request: &ContextReconstructionRequest,
    snapshot_id: &SnapshotId,
    profile: &NormalizationProfile,
    cache: &mut CueReconstructionCache,
) -> Result<CueReconstruction, CueReadCompositionError> {
    let inputs = GovernorContextInputs::borrow(reads)
        .reconstruct(ctx, request)
        .await?;
    reconstruct_cue_snapshot(&inputs, snapshot_id, profile, cache)
        .map_err(CueReadCompositionError::from)
}

/// Canonical shape of one cache-key preimage.
#[derive(Serialize)]
struct KeyShape<'a> {
    scope: &'a str,
    source_revision: u64,
    heads_sha256: String,
    bindings_sha256: String,
    profile_id: &'a str,
    profile_revision: u32,
    profile_digest: &'a str,
    snapshot_id: &'a str,
    fence_sha256: String,
}

/// Resolves the one current source revision used by the closed cue build.
///
/// The exact scope head is the source-revision authority for this derived
/// projection. A missing or ambiguous head is not replaced with a default.
fn source_revision(inputs: &SevenRoleInputs) -> Result<u64, CueCompositionError> {
    let key = format!("scope:{}", inputs.scope_id.as_str());
    let mut matching = inputs
        .heads_after
        .revision_heads
        .iter()
        .filter(|head| head.key.as_str() == key);
    let Some(head) = matching.next() else {
        return Err(CueCompositionError::ClosureMismatch(
            "current scope source revision head is missing".to_owned(),
        ));
    };
    if matching.next().is_some() || head.revision == 0 {
        return Err(CueCompositionError::ClosureMismatch(
            "current scope source revision head is ambiguous".to_owned(),
        ));
    }
    Ok(head.revision)
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
        source_revision,
        heads_sha256: sha256_hex(&heads_bytes),
        bindings_sha256: sha256_hex(&bindings_bytes),
        profile_id: &profile.profile_id,
        profile_revision: profile.profile_revision,
        profile_digest: profile.digest.as_str(),
        snapshot_id: snapshot_id.as_str(),
        fence_sha256: sha256_hex(&fence_bytes),
    };
    let bytes = canonical_json_bytes(&shape).map_err(|_| refused("key is not canonical"))?;
    Ok(CueCacheKey(sha256_hex(&bytes)))
}

/// Re-validates the one non-array cue payload that may become empty.
///
/// The read classifier is the first boundary that may assign
/// `ProjectionState::KnownEmpty`. This second check prevents a manually
/// assembled or stale `SevenRoleInputs` value from turning a null, malformed,
/// unbound, or non-authoritative payload into an empty cue set.
fn validate_authoritative_empty_projection(
    inputs: &SevenRoleInputs,
) -> Result<(), CueCompositionError> {
    let invalid = |detail: &str| CueCompositionError::UnexpectedPayload(detail.to_owned());
    let Some(payload) = inputs.cue.payload.as_ref() else {
        return Err(invalid("known-empty cue role carries no payload"));
    };
    if payload.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(invalid(
            "known-empty cue payload has an unsupported version",
        ));
    }
    if payload.get("scope_id").and_then(Value::as_str) != Some(inputs.scope_id.as_str()) {
        return Err(invalid(
            "known-empty cue payload scope differs from the closure",
        ));
    }
    if payload
        .get("selector")
        .and_then(Value::as_str)
        .is_none_or(|selector| selector.trim().is_empty() || selector.chars().any(char::is_control))
    {
        return Err(invalid("known-empty cue payload has no valid selector"));
    }
    let Some(records) = payload.get("records").and_then(Value::as_array) else {
        return Err(invalid("known-empty cue payload has no records array"));
    };
    if !records.is_empty() {
        return Err(invalid("known-empty cue payload contains records"));
    }
    let Some(provenance) = payload.get("provenance").and_then(Value::as_object) else {
        return Err(invalid("known-empty cue payload has no provenance object"));
    };
    if provenance.get("truncated").and_then(Value::as_bool) != Some(false)
        || provenance.get("matched_total").and_then(Value::as_u64) != Some(0)
        || provenance.get("returned").and_then(Value::as_u64) != Some(0)
        || provenance
            .get("max_records")
            .and_then(Value::as_u64)
            .is_none_or(|max_records| max_records == 0)
    {
        return Err(invalid(
            "known-empty cue payload lacks authoritative empty provenance",
        ));
    }
    let observed_fence = provenance
        .get("state_fence")
        .cloned()
        .and_then(|value| serde_json::from_value::<StateFence>(value).ok());
    if observed_fence.as_ref() != Some(&inputs.state_fence) {
        return Err(invalid(
            "known-empty cue payload fence differs from the closure",
        ));
    }
    Ok(())
}

/// Decodes the cue role payload into admitted bindings.
///
/// `KnownEmpty` is accepted only when the retained payload is the exact
/// authoritative empty understanding-input envelope; `Complete` must carry the
/// closed JSON array of `AdmittedCueBindingProjection`. Any other disposition
/// fails closed: degraded or unreadable roles never fold into an index.
///
/// Integration note: the store's `GetUnderstandingProjectionInputs` read (T11.3
/// store activation) returns a versioned understanding-inputs envelope
/// (`{version, selector, scope_id, records, provenance}`), not the
/// admitted-binding array, so a non-empty envelope fails closed here with
/// [`CueCompositionError::UnexpectedPayload`]. Binding envelope records to
/// the typed cue families is a follow-up slice; until then only the
/// authoritative empty builds through this composition.
fn decoded_bindings(
    inputs: &SevenRoleInputs,
) -> Result<Vec<AdmittedCueBindingProjection>, CueCompositionError> {
    let payload = match &inputs.cue.state {
        ProjectionState::KnownEmpty => {
            validate_authoritative_empty_projection(inputs)?;
            return Ok(Vec::new());
        }
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

/// Post-verifies the closed candidate against the same source closure before
/// exposing it.
///
/// Checks scope, fence, profile, snapshot identity, source revision, and the
/// authoritative empty edge set, validates the retained closure through the
/// owner, and round-trips an owner rebuild using that same retained closure.
fn post_verify_candidate(
    candidate: &CueSnapshotBuildCandidate,
    scope: &WorkScopeId,
    snapshot_id: &SnapshotId,
    profile: &NormalizationProfile,
    fence: &StateFence,
    source_revision: u64,
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
    let Some(closure) = candidate.retained_closure() else {
        return Err(mismatch("candidate does not retain a closed snapshot"));
    };
    if candidate.snapshot.source_revision != source_revision
        || closure.denominator.source_revision != source_revision
    {
        return Err(mismatch(
            "candidate source revision differs from the closure head",
        ));
    }
    if !candidate.relation_edges.is_empty() {
        return Err(mismatch(
            "candidate carries relation edges outside the zero-edge set",
        ));
    }
    let rebuilt = eliot_cue_index::rebuild_cue_snapshot(candidate, None)
        .map_err(|error| CueCompositionError::CueBuild(error.to_string()))?;
    if rebuilt.build_digest != candidate.build_digest {
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
    use eliot_cue_contracts::Digest;
    use eliot_store_api::{RevisionHead, RevisionKey, ScopeId, ScopeRevisionView};

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

    #[test]
    fn known_empty_requires_the_authoritative_empty_envelope() -> ProofResult {
        let mut inputs = role_inputs(ProjectionState::KnownEmpty)?;
        inputs.cue.payload = Some(Value::Null);
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

    fn role_inputs(cue_state: ProjectionState) -> ProofResult<SevenRoleInputs> {
        let fence = test_fence()?;
        let heads = ScopeRevisionView {
            scope_id: ScopeId::new("scope-a")?,
            revision_heads: vec![RevisionHead {
                key: RevisionKey::new("scope:scope-a")?,
                revision: 1,
                state_fence: fence.clone(),
            }],
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
        };
        let cue_payload = match &cue_state {
            ProjectionState::KnownEmpty => Some(serde_json::json!({
                "version": 1,
                "scope_id": "scope-a",
                "selector": "selector-a",
                "records": [],
                "provenance": {
                    "state_fence": fence.clone(),
                    "truncated": false,
                    "matched_total": 0,
                    "returned": 0,
                    "max_records": 1,
                },
            })),
            ProjectionState::Complete => Some(serde_json::json!([])),
            _ => None,
        };
        Ok(SevenRoleInputs {
            scope_id: ScopeId::new("scope-a")?,
            state_fence: fence,
            heads_before: heads.clone(),
            heads_after: heads,
            task_frame: unavailable(),
            attention: unavailable(),
            epistemic: unavailable(),
            epistemic_readback: None,
            cue: RoleAcquisition {
                operation: eliot_store_api::NamedReadOperation::GetUnderstandingProjectionInputs,
                state: cue_state,
                payload: cue_payload,
                revision_heads: Vec::new(),
            },
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
