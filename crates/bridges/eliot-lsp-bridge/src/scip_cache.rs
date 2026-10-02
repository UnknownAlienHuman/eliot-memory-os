//! Derived-cache reuse for SCIP projection items (issue #1898, I2.22).
//!
//! `finalize_scip` decodes sidecar bytes and projects per-operation items on
//! every call. That decode-plus-project derivation is deterministic, sync,
//! and verdict-free: this subsystem cannot express verdicts (see the crate
//! docs), and every receipt is recomputed per call with fresh
//! freshness/disposition/coverage/invoked-at values. This module consults the
//! retained [`DerivedCacheStore`](eliot_build_test_graph::DerivedCacheStore)
//! before deriving:
//!
//! ```text
//! hit  -> decode and projection are skipped; cached items return with a
//!         freshly assembled receipt (lineage only, never a verdict);
//! miss -> the genuine derivation runs (real decode plus real projection);
//!         its items are published; failures are never published.
//! ```
//!
//! Identity elements come only from genuine facts: the index digest over the
//! exact sidecar bytes, the caller configuration hash, the operation inputs,
//! the decoder identity of the parsing code, the offline-decode runtime
//! class, and caller-observed sidecar provenance (emitter, producer, root).
//! Absent provenance means no cache: callers pass `None` and get today's
//! exact uncached behavior. Nothing is invented to fill the closure.
//!
//! The cached subject is the per-operation projection items (small), not the
//! decoded index: a hit skips both the protobuf decode and the projection.
//! Items serialize deterministically with `serde_json`; the store verifies
//! content integrity on every read. A hit carries items plus lineage only.
//!
//! Because callers cannot know the items digest before deriving, the handle
//! memoizes observed content digests per `(index, operation)` key. The memo
//! holds digests only — no artifacts, no verdicts — so the store remains the
//! single enforcement framework (exact match, trust, integrity, rejection
//! log). Memo entries are evicted on any rejection so a poisoned entry can
//! never lodge, and failures are never published, so malformed input
//! re-derives (and fails honestly) on every call.

use std::collections::BTreeMap;

use eliot_build_test_graph::{
    CacheCounters, CacheLookup, CacheStoreError, DerivedCacheIdentity, DerivedCacheStore,
    FreshDerivation, RejectedCacheRecord, RootDisposition, TrustPolicy,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_instrument_scip::{SCIP_INSTRUMENT, ScipIndex};
use eliot_observability::CacheTelemetry;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    AnalyzerConfig, BridgeError, CandidateIdentity, Definition, InstrumentSpec,
    LspRegistryIdentity, LspStartedInvocation, RenameCandidate, ResolvedExecutableIdentityRecord,
    SemanticOperation, SourceCandidate, SymbolInfo, hex_bytes,
};

/// Runtime class bound into every cache identity.
///
/// Decoding runs offline over emitted bytes and never launches a process,
/// matching the decoder-only environment class recorded in the instrument
/// registry.
const RUNTIME_CLASS: &str = "offline-decode";

/// Maximum memoized content digests; oldest entries are evicted first.
///
/// Eviction only forces a cold re-derivation; correctness never depends on
/// the memo.
const MAX_MEMO_ENTRIES: usize = 256;

/// Caller-observed provenance of one SCIP sidecar emission.
///
/// Every field must be observed by the caller in the sidecar emitter
/// context. There is no discovery here: a caller without complete provenance
/// passes no cache and gets the exact uncached behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScipIndexerProvenance {
    /// Emitter family as observed (for example `scip-indexer`).
    pub indexer_name: String,
    /// Emitter version text as observed (required: absent facts mean no cache).
    pub indexer_version: String,
    /// Sidecar producer admitted by the caller policy.
    pub producer_id: String,
    /// Producer generation that emitted the sidecar.
    pub producer_generation: u64,
    /// Sidecar home as observed by the caller.
    pub root_identity: String,
    /// Observed root ACL digest (lowercase hex).
    pub root_acl_digest: String,
    /// Reparse/symlink disposition of the sidecar root as observed.
    pub root_disposition: RootDisposition,
}

/// Bounded derived-projection cache consulted by `finalize_scip`.
///
/// The handle owns the retained store, the caller trust policy, the observed
/// provenance, and the content-digest memo. It never launches a process,
/// admits work, or decides verification; it only decides reuse versus real
/// derivation.
pub struct ScipProjectionCache {
    store: DerivedCacheStore,
    trust: TrustPolicy,
    provenance: ScipIndexerProvenance,
    memo: BTreeMap<(String, String), MemoRecord>,
    sequence: u64,
    decodes_performed: u64,
    last_telemetry: Option<CacheTelemetry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MemoRecord {
    content_digest: String,
    sequence: u64,
}

#[derive(Clone, Debug)]
struct CacheIdentityOverrides {
    source_digest: String,
    config_digest: String,
    toolchain_version: String,
    compiler_version: String,
    parser_version: String,
    producer_id: String,
    producer_generation: u64,
}

#[derive(Serialize)]
struct ScipInvocationCommitmentV1<'a> {
    schema_version: u16,
    candidate: &'a SourceCandidate,
    source_tree_id: &'a str,
    source_kind: &'a eliot_artifact::ArtifactKind,
    source_content: &'a eliot_artifact::ContentAddress,
    source_binding: Option<&'a eliot_artifact::SourceBinding>,
    source_scope_at_dispatch: &'a Option<eliot_types::memory::GovernedGitScope>,
    candidate_identity_at_dispatch: &'a Option<CandidateIdentity>,
    build_fingerprint_at_dispatch: &'a Option<eliot_build_test_graph::BuildFingerprint>,
    config: &'a AnalyzerConfig,
    operation: &'a SemanticOperation,
    instrument: &'a str,
    instrument_kind: &'a eliot_instrument_api::InstrumentKind,
    instrument_profile: &'a str,
    instrument_target: &'a str,
    instrument_arguments: &'a [String],
    instrument_input_artifacts: &'a [eliot_contracts::ArtifactId],
    instrument_declared_scope: &'a str,
    resolved_executable: &'a ResolvedExecutableIdentityRecord,
    instrument_spec: &'a InstrumentSpec,
    registry_identity: &'a LspRegistryIdentity,
}

impl ScipProjectionCache {
    /// Creates a cache over an explicit store, trust policy, and observed
    /// provenance.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] when any provenance text is blank or carries
    /// control characters, or when the ACL digest is not a lowercase digest.
    /// Callers without complete facts must pass no cache instead.
    pub fn new(
        store: DerivedCacheStore,
        trust: TrustPolicy,
        provenance: ScipIndexerProvenance,
    ) -> Result<Self, BridgeError> {
        validate_provenance(&provenance)?;
        Ok(Self {
            store,
            trust,
            provenance,
            memo: BTreeMap::new(),
            sequence: 0,
            decodes_performed: 0,
            last_telemetry: None,
        })
    }

    /// Replaces the provenance after validating it, keeping the store.
    ///
    /// The shared store image lets one cache serve several emitters while
    /// trust still rejects every untrusted producer.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] when the replacement provenance is invalid;
    /// the previous provenance is kept in that case.
    pub fn reattest(&mut self, provenance: ScipIndexerProvenance) -> Result<(), BridgeError> {
        validate_provenance(&provenance)?;
        self.provenance = provenance;
        Ok(())
    }

    /// Real decoder runs performed through this handle.
    ///
    /// Incremented exactly where `ScipIndex::decode` runs, so a warm hit is
    /// proven by an unchanged counter.
    #[must_use]
    pub const fn decodes_performed(&self) -> u64 {
        self.decodes_performed
    }

    /// Current store observation counters.
    #[must_use]
    pub const fn counters(&self) -> CacheCounters {
        self.store.counters()
    }

    /// Rejection records in insertion order.
    #[must_use]
    pub fn rejected(&self) -> Vec<RejectedCacheRecord> {
        self.store.rejected()
    }

    /// Telemetry recorded by the most recent consultation, if any.
    #[must_use]
    pub fn last_telemetry(&self) -> Option<CacheTelemetry> {
        self.last_telemetry.clone()
    }

    /// Reuses cached items or runs the genuine decode-plus-project
    /// derivation.
    ///
    /// `config_hash` is the caller configuration hash and `operation` the
    /// requested projection; both enter the identity as genuine derivation
    /// inputs. `project` maps a freshly decoded index to typed items. Decode
    /// failures and projection failures propagate as [`BridgeError`] (the
    /// caller renders today's exact failure receipts); they are never
    /// published, so malformed input re-derives honestly on every call.
    /// Cache misses, rejections, and publish failures all fall through to
    /// freshly derived items: cache availability is never on the correctness
    /// path.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] when the genuine derivation fails. Cache
    /// problems are returned inside [`CachedProjection`] as `rejected`
    /// evidence, never as errors.
    pub fn reuse_or_derive(
        &mut self,
        index_bytes: &[u8],
        config_hash: &str,
        operation: &SemanticOperation,
        target_identity: &str,
        project: impl FnOnce(&ScipIndex) -> Result<CachedScipItems, BridgeError>,
    ) -> Result<CachedProjection, BridgeError> {
        let index_digest = digest_bytes(index_bytes);
        let op_digest = operation_digest(config_hash, operation);
        self.reuse_or_derive_with_identity(
            index_bytes,
            target_identity,
            &index_digest,
            &op_digest,
            None,
            project,
        )
    }

    /// Reuses projections only for the exact original retained invocation and
    /// its owner-minted source artifact. The sidecar bytes remain the generated
    /// input; source content, candidate selectors, admitted executable,
    /// instrument spec, and parser/registry identities enter the existing
    /// cache closure. The live start handle is opaque and cannot be rebuilt
    /// from a retained JSON projection.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError`] when the invocation has no live owner source
    /// proof or any original source/config/tool identity fails validation.
    pub fn reuse_or_derive_for_invocation(
        &mut self,
        index_bytes: &[u8],
        invocation: &LspStartedInvocation,
        target_identity: &str,
        project: impl FnOnce(&ScipIndex) -> Result<CachedScipItems, BridgeError>,
    ) -> Result<CachedProjection, BridgeError> {
        let overrides = invocation_cache_identity(invocation)?;
        let memo_key_digest = overrides.config_digest.clone();
        self.reuse_or_derive_with_identity(
            index_bytes,
            target_identity,
            &overrides.source_digest,
            &memo_key_digest,
            Some(overrides),
            project,
        )
    }

    fn reuse_or_derive_with_identity(
        &mut self,
        index_bytes: &[u8],
        target_identity: &str,
        source_digest: &str,
        op_digest: &str,
        overrides: Option<CacheIdentityOverrides>,
        project: impl FnOnce(&ScipIndex) -> Result<CachedScipItems, BridgeError>,
    ) -> Result<CachedProjection, BridgeError> {
        let index_digest = digest_bytes(index_bytes);
        let memo_key = (index_digest.clone(), op_digest.to_owned());
        if let Some(memo) = self.memo.get(&memo_key).cloned() {
            let identity = self.identity(
                source_digest,
                &index_digest,
                op_digest,
                &memo.content_digest,
                overrides.as_ref(),
            );
            match self.store.lookup(&identity, &self.trust) {
                CacheLookup::Hit(artifact) => {
                    match serde_json::from_slice::<CachedScipItems>(&artifact.bytes) {
                        Ok(items) => {
                            let telemetry = self.telemetry(
                                target_identity,
                                Some(artifact.lineage.identity_digest.clone()),
                                true,
                            )?;
                            return Ok(CachedProjection {
                                items,
                                cached: true,
                                rejected: None,
                                telemetry,
                            });
                        }
                        Err(_) => {
                            self.memo.remove(&memo_key);
                        }
                    }
                }
                CacheLookup::Miss { reason } => {
                    let rejected = if reason.is_recorded() {
                        self.store.rejected().pop()
                    } else {
                        None
                    };
                    return self.derive_fresh(
                        index_bytes,
                        target_identity,
                        &index_digest,
                        source_digest,
                        op_digest,
                        &memo_key,
                        rejected,
                        overrides.as_ref(),
                        project,
                    );
                }
            }
        }
        self.derive_fresh(
            index_bytes,
            target_identity,
            &index_digest,
            source_digest,
            op_digest,
            &memo_key,
            None,
            overrides.as_ref(),
            project,
        )
    }

    /// Runs the genuine derivation, publishes its items, and memoizes them.
    #[allow(clippy::too_many_arguments)]
    fn derive_fresh(
        &mut self,
        index_bytes: &[u8],
        target_identity: &str,
        index_digest: &str,
        source_digest: &str,
        op_digest: &str,
        memo_key: &(String, String),
        rejected: Option<RejectedCacheRecord>,
        overrides: Option<&CacheIdentityOverrides>,
        project: impl FnOnce(&ScipIndex) -> Result<CachedScipItems, BridgeError>,
    ) -> Result<CachedProjection, BridgeError> {
        let index = self.decode(index_bytes)?;
        let items = project(&index)?;
        let bytes = serde_json::to_vec(&items).map_err(|error| {
            BridgeError::ScipDecode(format!("cached projection failed to serialize: {error}"))
        })?;
        let content_digest = digest_bytes(&bytes);
        let identity = self.identity(
            source_digest,
            index_digest,
            op_digest,
            &content_digest,
            overrides,
        );
        match self.store.publish(
            &identity,
            &self.trust,
            FreshDerivation::new(bytes, 1, false),
        ) {
            Ok(artifact) => {
                self.memoize(memo_key, content_digest);
                let telemetry = self.telemetry(
                    target_identity,
                    Some(artifact.lineage.identity_digest),
                    false,
                )?;
                Ok(CachedProjection {
                    items,
                    cached: false,
                    rejected,
                    telemetry,
                })
            }
            Err(error) => {
                let latest = self.store.rejected().pop();
                if evicts_memo(&error) {
                    self.memo.remove(memo_key);
                }
                let telemetry = self.telemetry(target_identity, identity.digest().ok(), false)?;
                Ok(CachedProjection {
                    items,
                    cached: false,
                    rejected: latest.or(rejected),
                    telemetry,
                })
            }
        }
    }

    /// Runs the real decoder exactly once per call site invocation.
    fn decode(&mut self, index_bytes: &[u8]) -> Result<ScipIndex, BridgeError> {
        self.decodes_performed = self.decodes_performed.saturating_add(1);
        ScipIndex::decode(index_bytes).map_err(BridgeError::from)
    }

    /// Assembles the full closure identity from genuine facts only.
    ///
    /// The indexed bytes play two roles: the source closure and the
    /// generated-input closure, because generated content, if any, is
    /// contained in the indexed bytes and no separate generated-input
    /// channel exists at this entry. The parser version names the decoding
    /// code at its workspace release, so any decoder change ships a new
    /// identity and invalidates reuse.
    fn identity(
        &self,
        source_digest: &str,
        index_digest: &str,
        op_digest: &str,
        content_digest: &str,
        overrides: Option<&CacheIdentityOverrides>,
    ) -> DerivedCacheIdentity {
        DerivedCacheIdentity {
            source_digest: source_digest.to_owned(),
            generated_input_digest: index_digest.to_owned(),
            toolchain_version: overrides.map_or_else(
                || self.provenance.indexer_name.clone(),
                |identity| identity.toolchain_version.clone(),
            ),
            compiler_version: overrides.map_or_else(
                || self.provenance.indexer_version.clone(),
                |identity| identity.compiler_version.clone(),
            ),
            parser_version: overrides.map_or_else(
                || format!("{}/{}", SCIP_INSTRUMENT, env!("CARGO_PKG_VERSION")),
                |identity| identity.parser_version.clone(),
            ),
            runtime_version: RUNTIME_CLASS.to_owned(),
            config_digest: overrides.map_or_else(
                || op_digest.to_owned(),
                |identity| identity.config_digest.clone(),
            ),
            producer_id: overrides.map_or_else(
                || self.provenance.producer_id.clone(),
                |identity| identity.producer_id.clone(),
            ),
            producer_generation: overrides
                .map_or(self.provenance.producer_generation, |identity| {
                    identity.producer_generation
                }),
            root_identity: self.provenance.root_identity.clone(),
            root_acl_digest: self.provenance.root_acl_digest.clone(),
            root_disposition: self.provenance.root_disposition,
            schema_revision: eliot_build_test_graph::DERIVED_CACHE_SCHEMA_V1.to_owned(),
            content_digest: content_digest.to_owned(),
        }
    }

    fn memoize(&mut self, memo_key: &(String, String), content_digest: String) {
        self.sequence = self.sequence.saturating_add(1);
        while self.memo.len() >= MAX_MEMO_ENTRIES
            && let Some(oldest) = self
                .memo
                .iter()
                .min_by_key(|(_, record)| record.sequence)
                .map(|(key, _)| key.clone())
        {
            self.memo.remove(&oldest);
        }
        self.memo.insert(
            memo_key.clone(),
            MemoRecord {
                content_digest,
                sequence: self.sequence,
            },
        );
    }

    fn telemetry(
        &mut self,
        target_identity: &str,
        cache_identity: Option<String>,
        cached: bool,
    ) -> Result<CacheTelemetry, BridgeError> {
        let counters = self.store.counters();
        let telemetry = CacheTelemetry::from_cache_measurements(
            target_identity,
            cache_identity,
            None,
            Some(cached),
            counters.hit_rate(),
            self.store.last_derive_duration_ms(),
            self.store.last_warm_duration_ms(),
            Some(self.store.stored_bytes()),
            Some(counters.invalidation_count()),
        )
        .map_err(|error| BridgeError::ScipDecode(format!("cache telemetry: {error}")))?;
        self.last_telemetry = Some(telemetry.clone());
        Ok(telemetry)
    }
}

/// One cacheable projection: typed items plus reuse evidence.
///
/// The items carry no verdict: receipts are assembled fresh per call by the
/// entrypoint. `cached` reports reuse; `rejected` carries any recorded cache
/// rejection observed while consulting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedProjection {
    /// Reused or freshly derived items.
    pub items: CachedScipItems,
    /// Whether the items came from a verified cache hit.
    pub cached: bool,
    /// Rejection recorded while consulting the cache, if any.
    pub rejected: Option<RejectedCacheRecord>,
    /// Owner-projected cache telemetry for this consultation.
    pub telemetry: CacheTelemetry,
}

/// Typed projection items round-tripping through the cache as canonical JSON.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CachedScipItems {
    /// Definition locations for one symbol.
    Definitions(Vec<Definition>),
    /// Reference locations for one symbol.
    References(Vec<Reference>),
    /// Symbol-table entries under one path scope.
    Symbols(Vec<SymbolInfo>),
    /// Unapplied rename candidate.
    Rename(RenameCandidate),
}

/// Reports whether a publish failure invalidates the memoized content mapping.
///
/// Identity-level rejections (untrusted producer/root, unsupported schema,
/// malformed identity) leave the observed content mapping intact: the same
/// closure still derives the same bytes. Content-level rejections (digest
/// mismatch, oversize payload, narrower-union refusal) invalidate it, so the
/// memo entry is dropped and the next call re-derives cold.
fn evicts_memo(error: &CacheStoreError) -> bool {
    matches!(
        error,
        CacheStoreError::ContentMismatch { .. }
            | CacheStoreError::EntryTooLarge { .. }
            | CacheStoreError::NarrowerUnionWithoutReplacement { .. }
    )
}

/// Lowercase hex digest over bytes.
fn digest_bytes(bytes: &[u8]) -> String {
    hex_bytes(Sha256::digest(bytes).as_slice())
}

/// Digest over the genuine derivation inputs beyond the index bytes: the
/// caller configuration hash plus the exact operation.
fn operation_digest(config_hash: &str, operation: &SemanticOperation) -> String {
    let material = match operation {
        SemanticOperation::Definitions { symbol } => format!("definitions\0{symbol}"),
        SemanticOperation::References { symbol } => format!("references\0{symbol}"),
        SemanticOperation::Symbols { path_scope } => format!("symbols\0{path_scope}"),
        SemanticOperation::Diagnostics => "diagnostics".to_owned(),
        SemanticOperation::Rename { symbol, new_name } => {
            format!("rename\0{symbol}\0{new_name}")
        }
        SemanticOperation::ProbeVersion => "probe-version".to_owned(),
    };
    digest_bytes(format!("{config_hash}\0{material}").as_bytes())
}

fn invocation_cache_identity(
    invocation: &LspStartedInvocation,
) -> Result<CacheIdentityOverrides, BridgeError> {
    invocation.config.validate()?;
    invocation.source_candidate.validate()?;
    if !matches!(
        &invocation.operation,
        SemanticOperation::Definitions { .. }
            | SemanticOperation::References { .. }
            | SemanticOperation::Symbols { .. }
            | SemanticOperation::Rename { .. }
    ) || !super::operation_matches_config(&invocation.operation, &invocation.config)
        || !super::candidate_selectors_match_operation(
            &invocation.source_candidate,
            &invocation.operation,
        )
    {
        return Err(BridgeError::UnsupportedOperation);
    }

    let proof = invocation.source_artifact_proof.as_ref().ok_or_else(|| {
        BridgeError::InconsistentBinding(
            "bound SCIP cache requires the original live source-artifact proof".to_owned(),
        )
    })?;
    if !proof
        .snapshot
        .validates_workspace_root(std::path::Path::new(
            &invocation.source_candidate.workspace_root,
        ))
        .map_err(BridgeError::SourceSnapshot)?
        || !super::source_artifact_binds_invocation(proof, &invocation.instrument_invocation)
    {
        return Err(BridgeError::InconsistentBinding(
            "owner source proof does not bind the admitted SCIP candidate and invocation"
                .to_owned(),
        ));
    }

    super::validate_candidate_identity(
        invocation.candidate_identity.as_ref(),
        invocation.build_fingerprint.as_ref(),
    )?;
    if let Some(scope) = invocation.source_scope_at_dispatch.as_ref() {
        super::validate_git_scope(scope)?;
    }
    super::validate_instrument_spec(&invocation.instrument_spec)?;
    let resolved = invocation
        .resolved_executable
        .resolve(invocation.registry_identity.instrument.as_str())?;
    let (expected_parser, _) = super::expected_parser_and_normalizer(&invocation.operation);
    if !resolved.is_complete()
        || invocation.registry_identity.instrument != invocation.instrument_invocation.instrument
        || invocation.registry_identity.parser != invocation.instrument_spec.parser
        || invocation.registry_identity.parser.as_str() != expected_parser
        || !super::registry_projection_is_internally_consistent(&invocation.registry_identity)
    {
        return Err(BridgeError::InconsistentBinding(
            "original executable, SCIP instrument, parser, or registry identities disagree"
                .to_owned(),
        ));
    }

    let source = proof.projection();
    super::validate_source_artifact_identity(&proof.snapshot, &source.artifact_reference)?;
    let identity = &source.artifact_reference.identity;
    let commitment = ScipInvocationCommitmentV1 {
        schema_version: 1,
        candidate: &invocation.source_candidate,
        source_tree_id: &source.git_tree_id,
        source_kind: &identity.kind,
        source_content: &identity.content,
        source_binding: identity.source.as_ref(),
        source_scope_at_dispatch: &invocation.source_scope_at_dispatch,
        candidate_identity_at_dispatch: &invocation.candidate_identity,
        build_fingerprint_at_dispatch: &invocation.build_fingerprint,
        config: &invocation.config,
        operation: &invocation.operation,
        instrument: invocation.instrument_invocation.instrument.as_str(),
        instrument_kind: &invocation.instrument_invocation.kind,
        instrument_profile: &invocation.instrument_invocation.profile,
        instrument_target: &invocation.instrument_invocation.target,
        instrument_arguments: &invocation.instrument_invocation.arguments,
        instrument_input_artifacts: &invocation.instrument_invocation.input_artifacts,
        instrument_declared_scope: &invocation.instrument_invocation.declared_scope,
        resolved_executable: &invocation.resolved_executable,
        instrument_spec: &invocation.instrument_spec,
        registry_identity: &invocation.registry_identity,
    };
    let commitment_bytes = canonical_json_bytes(&commitment)
        .map_err(|error| BridgeError::InconsistentBinding(error.to_string()))?;
    let parser_version = format!(
        "{}@{};normalizer={};invalidation={}",
        invocation.registry_identity.parser,
        invocation.instrument_spec.parser_generation,
        invocation.registry_identity.normalizer,
        invocation.registry_identity.invalidation.parser,
    );

    Ok(CacheIdentityOverrides {
        source_digest: identity.content.digest_hex.clone(),
        config_digest: sha256_hex(&commitment_bytes),
        toolchain_version: invocation.registry_identity.toolchain.clone(),
        compiler_version: invocation
            .resolved_executable
            .tool_version
            .clone()
            .unwrap_or_else(|| invocation.resolved_executable.content_digest.clone()),
        parser_version,
        producer_id: invocation.registry_identity.instrument.as_str().to_owned(),
        producer_generation: invocation.registry_identity.generation,
    })
}

fn validate_provenance(provenance: &ScipIndexerProvenance) -> Result<(), BridgeError> {
    for (value, field) in [
        (provenance.indexer_name.as_str(), "indexer_name"),
        (provenance.indexer_version.as_str(), "indexer_version"),
        (provenance.producer_id.as_str(), "producer_id"),
        (provenance.root_identity.as_str(), "root_identity"),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(BridgeError::InvalidText { field });
        }
    }
    if provenance.root_acl_digest.len() != 64
        || provenance
            .root_acl_digest
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(BridgeError::InvalidConfig(
            "root_acl_digest must be a lowercase SHA-256 digest".to_owned(),
        ));
    }
    Ok(())
}
