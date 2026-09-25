//! I2.22 derived-cache reuse enforcement for governed build artifacts.
//!
//! Reuse of a derived cache entry is bound to the exact dependency closure:
//! source and generated-input digests; toolchain, compiler, parser, and
//! runtime versions; configuration/features/environment fingerprint; producer
//! identity and generation; cache-root identity, ACL digest, and
//! reparse/symlink disposition; format/schema revision; and content integrity
//! digest.
//!
//! Enforcement rules, applied by [`DerivedCacheStore`]:
//!
//! ```text
//! checksum detects corruption but does not authenticate producer or root;
//! missing, unreadable, untrusted, or mismatched cache is a cache miss,
//! never a correctness failure;
//! no correctness path depends on cache availability: the uncached derivation
//! always runs on a miss, even when the store itself rejects the publish;
//! a hit carries artifact lineage but never an old test/verifier verdict
//! (the hit type has no verdict field by construction);
//! a narrower subset derivation cannot overwrite a broader valid union entry
//! unless replacement semantics are explicitly declared;
//! partial loads preserve known-good entries and record rejected entries.
//! ```

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::{GraphError, digest_bytes_for};

/// Admitted derived-cache schema revision.
///
/// Entries carrying any other revision are treated as a cache miss
/// ([`CacheRejectReason::UnsupportedSchema`]), never as a correctness failure.
pub const DERIVED_CACHE_SCHEMA_V1: &str = "eliot.derived-cache/v1";

/// Schema revisions this enforcement layer admits for reuse.
pub const ADMITTED_SCHEMA_REVISIONS: &[&str] = &[DERIVED_CACHE_SCHEMA_V1];

/// Default bound on retained cache entries.
pub const DEFAULT_MAX_ENTRIES: usize = 256;
/// Default bound on retained cache payload bytes (64 MiB).
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Default bound on retained rejection records.
pub const DEFAULT_MAX_REJECTIONS: usize = 256;

/// Reparse/symlink disposition of the cache root that produced an entry.
///
/// The disposition is part of cache identity: a root observed through a
/// symlink or reparse point is never interchangeable with a direct root.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum RootDisposition {
    /// The cache root was addressed directly.
    Direct,
    /// The cache root was addressed through a symlink.
    Symlink,
    /// The cache root was addressed through a reparse point.
    ReparsePoint,
}

/// Exact dependency closure binding one derived-cache entry (I2.22).
///
/// Every field participates in the identity digest: altering any declared
/// element changes the digest and therefore forces a cache miss followed by
/// a fresh uncached derivation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DerivedCacheIdentity {
    /// Digest over the exact source closure.
    pub source_digest: String,
    /// Digest over generated inputs (build scripts, proc macros, codegen).
    pub generated_input_digest: String,
    /// Toolchain version text (for example `rustc 1.89.0 (x86_64-pc-windows-msvc)`).
    pub toolchain_version: String,
    /// Compiler version text observed for the producing executable.
    pub compiler_version: String,
    /// Parser/normalizer contract version text.
    pub parser_version: String,
    /// Runtime version or environment class text.
    pub runtime_version: String,
    /// Fingerprint digest covering configuration, features, and environment.
    pub config_digest: String,
    /// Identity of the artifact producer admitted to write this entry.
    pub producer_id: String,
    /// Producer generation that derived the entry.
    pub producer_generation: u64,
    /// Identity of the cache root holding the entry.
    pub root_identity: String,
    /// Digest over the cache-root ACL observed at derivation time.
    pub root_acl_digest: String,
    /// Reparse/symlink disposition of the cache root.
    pub root_disposition: RootDisposition,
    /// Format/schema revision of the cached artifact bytes.
    pub schema_revision: String,
    /// Integrity digest the cached artifact bytes must reproduce.
    pub content_digest: String,
}

impl DerivedCacheIdentity {
    /// Validates every closure element without authenticating anything.
    ///
    /// Validation establishes shape (non-blank text, well-formed digests).
    /// Authentication of producer and root happens against [`TrustPolicy`]
    /// at lookup and publish time: a checksum never authenticates them.
    pub fn validate(&self) -> Result<(), GraphError> {
        for (value, field) in [
            (&self.source_digest, "source_digest"),
            (&self.generated_input_digest, "generated_input_digest"),
            (&self.config_digest, "config_digest"),
            (&self.root_acl_digest, "root_acl_digest"),
            (&self.content_digest, "content_digest"),
        ] {
            crate::validate_digest_shape(value, field)?;
        }
        for (value, field) in [
            (&self.toolchain_version, "toolchain_version"),
            (&self.compiler_version, "compiler_version"),
            (&self.parser_version, "parser_version"),
            (&self.runtime_version, "runtime_version"),
            (&self.producer_id, "producer_id"),
            (&self.root_identity, "root_identity"),
            (&self.schema_revision, "schema_revision"),
        ] {
            crate::validate_text_shape(value, field)?;
        }
        Ok(())
    }

    /// Canonical identity digest over the full closure.
    pub fn digest(&self) -> Result<String, GraphError> {
        self.validate()?;
        digest_bytes_for(self)
    }
}

/// Authentication policy for cache producers and cache roots.
///
/// Checksums detect corruption but never authenticate: reuse additionally
/// requires the identity's producer and root to be members of these sets.
/// The empty policy denies everything (fail-closed default).
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrustPolicy {
    /// Producer identities admitted to supply reusable entries.
    pub trusted_producers: BTreeSet<String>,
    /// Cache-root identities admitted to hold reusable entries.
    pub trusted_roots: BTreeSet<String>,
}

impl TrustPolicy {
    /// Builds a policy from explicit allow-lists.
    pub fn new(
        trusted_producers: Vec<String>,
        trusted_roots: Vec<String>,
    ) -> Result<Self, GraphError> {
        for producer in &trusted_producers {
            crate::validate_text_shape(producer, "trusted_producer")?;
        }
        for root in &trusted_roots {
            crate::validate_text_shape(root, "trusted_root")?;
        }
        Ok(Self {
            trusted_producers: trusted_producers.into_iter().collect(),
            trusted_roots: trusted_roots.into_iter().collect(),
        })
    }

    /// Whether `identity` is authenticated for reuse.
    ///
    /// Returns the exact rejection cause when it is not.
    pub fn authenticate(&self, identity: &DerivedCacheIdentity) -> Result<(), CacheRejectReason> {
        if !self.trusted_producers.contains(&identity.producer_id) {
            return Err(CacheRejectReason::UntrustedProducer);
        }
        if !self.trusted_roots.contains(&identity.root_identity) {
            return Err(CacheRejectReason::UntrustedRoot);
        }
        Ok(())
    }
}

/// Exact cause of one cache miss.
///
/// Every cause except [`CacheRejectReason::EntryMissing`] is recorded in the
/// store rejection log; a cold miss on an absent entry is normal operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CacheRejectReason {
    /// The requested identity is malformed, so no entry could match it.
    UnvalidatedIdentity {
        /// Failing field or detail from validation.
        detail: String,
    },
    /// The producer is not in the trust policy.
    UntrustedProducer,
    /// The cache root is not in the trust policy.
    UntrustedRoot,
    /// The schema revision is not admitted for reuse.
    UnsupportedSchema {
        /// Revision carried by the request or entry.
        revision: String,
    },
    /// No entry exists under the identity digest (cold miss, not recorded).
    EntryMissing,
    /// The stored bytes are structurally unreadable (length inconsistency).
    Unreadable,
    /// The stored bytes fail the content integrity digest (corruption).
    ContentCorrupt {
        /// Digest the entry must reproduce.
        expected: String,
        /// Digest recomputed over the stored bytes.
        actual: String,
    },
    /// Derived bytes do not reproduce the declared content digest.
    ContentMismatch {
        /// Digest declared by the identity.
        expected: String,
        /// Digest computed over the derived bytes.
        actual: String,
    },
    /// A single derived payload exceeds the store byte bound.
    EntryTooLarge {
        /// Observed payload length in bytes.
        byte_len: u64,
    },
    /// A narrower subset derivation attempted to overwrite a broader valid
    /// union entry without declared replacement semantics.
    NarrowerUnionWithoutReplacement {
        /// Breadth of the preserved valid entry.
        existing_breadth: u64,
        /// Breadth of the refused candidate.
        candidate_breadth: u64,
    },
}

impl CacheRejectReason {
    /// Whether this cause is recorded in the rejection log.
    #[must_use]
    pub const fn is_recorded(&self) -> bool {
        !matches!(self, Self::EntryMissing)
    }
}

/// One recorded rejected-cache observation.
///
/// Rejection is evidence, never a correctness failure: the derivation that
/// observed it always falls through to the uncached path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RejectedCacheRecord {
    /// Identity digest that was requested, when one could be computed.
    pub identity_digest: Option<String>,
    /// Exact rejection cause.
    pub reason: CacheRejectReason,
    /// Monotonic store sequence number for ordering.
    pub sequence: u64,
}

/// Artifact lineage carried by a cache hit.
///
/// The hit carries provenance only: producer, root (including its ACL and
/// disposition), schema, and digests. There is deliberately no test or
/// verifier verdict field; verdicts stay candidate-bound and a hit can never
/// supply a previous candidate's verdict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactLineage {
    /// Producer identity that derived the artifact.
    pub producer_id: String,
    /// Producer generation that derived the artifact.
    pub producer_generation: u64,
    /// Cache-root identity the artifact was read from.
    pub root_identity: String,
    /// Digest over the cache-root ACL observed when the artifact was derived.
    pub root_acl_digest: String,
    /// Reparse/symlink disposition of the cache root.
    pub root_disposition: RootDisposition,
    /// Schema revision of the artifact bytes.
    pub schema_revision: String,
    /// Identity digest of the closure that produced the artifact.
    pub identity_digest: String,
    /// Integrity digest of the artifact bytes.
    pub content_digest: String,
}

impl ArtifactLineage {
    /// Validates the shape of every lineage element.
    ///
    /// This is deliberately a separate check at the hit boundary: copying a
    /// lineage projection must not make an empty or malformed ACL digest look
    /// like a reusable cache entry. Authentication remains the trust policy's
    /// responsibility; this method only validates representation shape.
    pub fn validate(&self) -> Result<(), GraphError> {
        for (value, field) in [
            (&self.root_acl_digest, "root_acl_digest"),
            (&self.identity_digest, "identity_digest"),
            (&self.content_digest, "content_digest"),
        ] {
            crate::validate_digest_shape(value, field)?;
        }
        for (value, field) in [
            (&self.producer_id, "producer_id"),
            (&self.root_identity, "root_identity"),
            (&self.schema_revision, "schema_revision"),
        ] {
            crate::validate_text_shape(value, field)?;
        }
        // The typed enum has no unchecked variants; keep its admitted set
        // explicit at the lineage boundary.
        match self.root_disposition {
            RootDisposition::Direct | RootDisposition::Symlink | RootDisposition::ReparsePoint => {}
        }
        Ok(())
    }
}

/// A reusable derived artifact: lineage plus bytes, never verdicts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedArtifact {
    /// Provenance carried by the hit.
    pub lineage: ArtifactLineage,
    /// Exact artifact bytes.
    pub bytes: Vec<u8>,
}

impl CachedArtifact {
    /// Builds the lineage view of a freshly derived payload.
    #[must_use]
    pub fn fresh(identity: &DerivedCacheIdentity, identity_digest: &str, bytes: Vec<u8>) -> Self {
        Self {
            lineage: ArtifactLineage {
                producer_id: identity.producer_id.clone(),
                producer_generation: identity.producer_generation,
                root_identity: identity.root_identity.clone(),
                root_acl_digest: identity.root_acl_digest.clone(),
                root_disposition: identity.root_disposition,
                schema_revision: identity.schema_revision.clone(),
                identity_digest: identity_digest.to_owned(),
                content_digest: identity.content_digest.clone(),
            },
            bytes,
        }
    }
}

/// Fresh output of one real uncached derivation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshDerivation {
    /// Artifact bytes produced without consulting the cache.
    pub bytes: Vec<u8>,
    /// Union breadth this derivation covers (members observed together).
    pub coverage_breadth: u64,
    /// Whether the cache contract declares replacement semantics allowing
    /// this derivation to overwrite a broader valid union entry.
    pub replacement_declared: bool,
}

impl FreshDerivation {
    /// Records one uncached derivation result.
    #[must_use]
    pub const fn new(bytes: Vec<u8>, coverage_breadth: u64, replacement_declared: bool) -> Self {
        Self {
            bytes,
            coverage_breadth,
            replacement_declared,
        }
    }
}

/// Outcome of one cache consultation with fallthrough derivation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivationOutcome {
    /// Artifact to use: reused on a hit, freshly derived on a miss.
    pub artifact: CachedArtifact,
    /// Whether the artifact came from a verified cache hit.
    pub cached: bool,
    /// Rejection recorded while consulting the cache, if any.
    pub rejected: Option<RejectedCacheRecord>,
    /// Wall time spent in the uncached derivation, if one ran.
    pub derive_duration_ms: Option<u64>,
}

/// Result of a read-only cache consultation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheLookup {
    /// A verified entry: exact closure, trusted producer/root, intact bytes.
    Hit(CachedArtifact),
    /// Any other case: run the real uncached derivation instead.
    Miss {
        /// Exact miss cause.
        reason: CacheRejectReason,
    },
}

/// Typed store failures.
///
/// A publish failure never fails the derivation it accompanies: the caller
/// still returns the freshly derived bytes. The failure is recorded as a
/// rejection so the invalidation stays visible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheStoreError {
    /// The identity is malformed.
    InvalidIdentity(String),
    /// The producer is not trusted.
    UntrustedProducer,
    /// The cache root is not trusted.
    UntrustedRoot,
    /// The schema revision is not admitted.
    UnsupportedSchema(String),
    /// Derived bytes do not reproduce the declared content digest.
    ContentMismatch {
        /// Digest declared by the identity.
        expected: String,
        /// Digest computed over the derived bytes.
        actual: String,
    },
    /// The payload exceeds the store byte bound.
    EntryTooLarge {
        /// Observed payload length in bytes.
        byte_len: u64,
    },
    /// A narrower subset derivation attempted to overwrite a broader valid
    /// union entry without declared replacement semantics.
    NarrowerUnionWithoutReplacement {
        /// Breadth of the preserved valid entry.
        existing_breadth: u64,
        /// Breadth of the refused candidate.
        candidate_breadth: u64,
    },
}

/// Bounds for one [`DerivedCacheStore`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CacheLimits {
    /// Maximum retained entries; oldest entries are evicted first.
    pub max_entries: usize,
    /// Maximum retained payload bytes across all entries.
    pub max_bytes: u64,
    /// Maximum retained rejection records; oldest are dropped first.
    pub max_rejections: usize,
}

impl CacheLimits {
    /// Builds explicit bounds; every bound must be non-zero.
    pub const fn new(
        max_entries: usize,
        max_bytes: u64,
        max_rejections: usize,
    ) -> Result<Self, GraphError> {
        if max_entries == 0 {
            return Err(GraphError::Empty {
                field: "cache_limits.max_entries",
            });
        }
        if max_bytes == 0 {
            return Err(GraphError::Empty {
                field: "cache_limits.max_bytes",
            });
        }
        if max_rejections == 0 {
            return Err(GraphError::Empty {
                field: "cache_limits.max_rejections",
            });
        }
        Ok(Self {
            max_entries,
            max_bytes,
            max_rejections,
        })
    }
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
            max_rejections: DEFAULT_MAX_REJECTIONS,
        }
    }
}

/// Observation counters for instrument economics.
///
/// Hits and misses yield the hit rate; derivations count cold uncached runs;
/// rejections count invalidations; stores and evictions with
/// [`DerivedCacheStore::stored_bytes`] describe cache size behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CacheCounters {
    /// Verified reuse hits.
    pub hits: u64,
    /// Misses that fell through to uncached derivation.
    pub misses: u64,
    /// Recorded rejections (invalidations).
    pub rejections: u64,
    /// Successful publishes.
    pub stores: u64,
    /// Capacity evictions.
    pub evictions: u64,
    /// Uncached derivations executed.
    pub derivations: u64,
}

impl CacheCounters {
    /// Hit rate over all consultations, or `None` before the first one.
    ///
    /// The rate is telemetry, not proof: beyond 2^53 consultations the
    /// float mantissa cannot represent every count exactly.
    #[allow(
        clippy::cast_precision_loss,
        reason = "hit rate is approximate telemetry, never an enforcement input"
    )]
    #[must_use]
    pub fn hit_rate(&self) -> Option<f64> {
        let total = self.hits.saturating_add(self.misses);
        if total == 0 {
            return None;
        }
        Some(self.hits as f64 / total as f64)
    }

    /// Total observed invalidations from rejected entries and capacity
    /// evictions.
    #[must_use]
    pub const fn invalidation_count(&self) -> u64 {
        self.rejections.saturating_add(self.evictions)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredEntry {
    identity: DerivedCacheIdentity,
    bytes: Vec<u8>,
    byte_len: u64,
    coverage_breadth: u64,
    sequence: u64,
}

/// Bounded in-memory derived cache with exact-closure reuse enforcement.
///
/// The store owns no filesystem, process, scheduler, or verdict: it keeps
/// verified payload bytes keyed by identity digest, records rejections, and
/// always falls through to caller-supplied uncached derivation on any miss.
#[derive(Clone, Debug)]
pub struct DerivedCacheStore {
    entries: BTreeMap<String, StoredEntry>,
    rejected: VecDeque<RejectedCacheRecord>,
    counters: CacheCounters,
    limits: CacheLimits,
    sequence: u64,
    stored_bytes: u64,
    last_derive_duration_ms: Option<u64>,
    last_warm_duration_ms: Option<u64>,
}

impl DerivedCacheStore {
    /// Creates an empty store under explicit bounds.
    pub const fn new(limits: CacheLimits) -> Self {
        Self {
            entries: BTreeMap::new(),
            rejected: VecDeque::new(),
            counters: CacheCounters {
                hits: 0,
                misses: 0,
                rejections: 0,
                stores: 0,
                evictions: 0,
                derivations: 0,
            },
            limits,
            sequence: 0,
            stored_bytes: 0,
            last_derive_duration_ms: None,
            last_warm_duration_ms: None,
        }
    }

    /// Current observation counters.
    #[must_use]
    pub const fn counters(&self) -> CacheCounters {
        self.counters
    }

    /// Rejection records in insertion order.
    #[must_use]
    pub fn rejected(&self) -> Vec<RejectedCacheRecord> {
        self.rejected.iter().cloned().collect()
    }

    /// Number of retained entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Retained payload bytes across all entries.
    #[must_use]
    pub const fn stored_bytes(&self) -> u64 {
        self.stored_bytes
    }

    /// Wall time of the most recent uncached derivation, if one ran.
    #[must_use]
    pub const fn last_derive_duration_ms(&self) -> Option<u64> {
        self.last_derive_duration_ms
    }

    /// Wall time of the most recent verified warm cache lookup, if one ran.
    #[must_use]
    pub const fn last_warm_duration_ms(&self) -> Option<u64> {
        self.last_warm_duration_ms
    }

    /// Whether an entry exists under an identity digest.
    #[must_use]
    pub fn contains(&self, identity_digest: &str) -> bool {
        self.entries.contains_key(identity_digest)
    }

    fn next_sequence(&mut self) -> u64 {
        self.sequence = self.sequence.saturating_add(1);
        self.sequence
    }

    fn record_rejection(
        &mut self,
        identity_digest: Option<String>,
        reason: CacheRejectReason,
    ) -> RejectedCacheRecord {
        let sequence = self.next_sequence();
        let record = RejectedCacheRecord {
            identity_digest,
            reason,
            sequence,
        };
        if self.rejected.len() >= self.limits.max_rejections {
            self.rejected.pop_front();
        }
        self.rejected.push_back(record.clone());
        self.counters.rejections = self.counters.rejections.saturating_add(1);
        record
    }

    /// Consults the cache without deriving anything.
    ///
    /// Any absent, unreadable, untrusted, corrupt, or mismatched element
    /// yields [`CacheLookup::Miss`]: the caller must run the real uncached
    /// derivation. Recorded rejections preserve broader valid entries: only
    /// the offending entry is removed, never its neighbors.
    pub fn lookup(&mut self, identity: &DerivedCacheIdentity, trust: &TrustPolicy) -> CacheLookup {
        let lookup_started = Instant::now();
        if let Err(error) = identity.validate() {
            let record = self.record_rejection(
                None,
                CacheRejectReason::UnvalidatedIdentity {
                    detail: error.to_string(),
                },
            );
            self.counters.misses = self.counters.misses.saturating_add(1);
            return CacheLookup::Miss {
                reason: record.reason.clone(),
            };
        }
        if let Err(reason) = trust.authenticate(identity) {
            let key = identity.digest().ok();
            let record = self.record_rejection(key, reason.clone());
            self.counters.misses = self.counters.misses.saturating_add(1);
            return CacheLookup::Miss {
                reason: record.reason.clone(),
            };
        }
        if !ADMITTED_SCHEMA_REVISIONS.contains(&identity.schema_revision.as_str()) {
            let key = identity.digest().ok();
            let reason = CacheRejectReason::UnsupportedSchema {
                revision: identity.schema_revision.clone(),
            };
            let record = self.record_rejection(key, reason.clone());
            self.counters.misses = self.counters.misses.saturating_add(1);
            return CacheLookup::Miss {
                reason: record.reason.clone(),
            };
        }
        let key = match identity.digest() {
            Ok(key) => key,
            Err(error) => {
                let record = self.record_rejection(
                    None,
                    CacheRejectReason::UnvalidatedIdentity {
                        detail: error.to_string(),
                    },
                );
                self.counters.misses = self.counters.misses.saturating_add(1);
                return CacheLookup::Miss {
                    reason: record.reason.clone(),
                };
            }
        };
        let Some(stored) = self.entries.get(&key).cloned() else {
            self.counters.misses = self.counters.misses.saturating_add(1);
            return CacheLookup::Miss {
                reason: CacheRejectReason::EntryMissing,
            };
        };
        if stored.identity != *identity {
            self.entries.remove(&key);
            self.stored_bytes = self.stored_bytes.saturating_sub(stored.byte_len);
            let reason = CacheRejectReason::ContentMismatch {
                expected: identity.content_digest.clone(),
                actual: stored.identity.content_digest.clone(),
            };
            let record = self.record_rejection(Some(key), reason.clone());
            self.counters.misses = self.counters.misses.saturating_add(1);
            return CacheLookup::Miss {
                reason: record.reason.clone(),
            };
        }
        let observed_len = u64::try_from(stored.bytes.len()).unwrap_or(u64::MAX);
        if observed_len != stored.byte_len {
            self.entries.remove(&key);
            self.stored_bytes = self.stored_bytes.saturating_sub(stored.byte_len);
            let record = self.record_rejection(Some(key), CacheRejectReason::Unreadable);
            self.counters.misses = self.counters.misses.saturating_add(1);
            return CacheLookup::Miss {
                reason: record.reason.clone(),
            };
        }
        let actual = crate::sha256_of(&stored.bytes);
        if actual != identity.content_digest {
            self.entries.remove(&key);
            self.stored_bytes = self.stored_bytes.saturating_sub(stored.byte_len);
            let reason = CacheRejectReason::ContentCorrupt {
                expected: identity.content_digest.clone(),
                actual,
            };
            let record = self.record_rejection(Some(key), reason.clone());
            self.counters.misses = self.counters.misses.saturating_add(1);
            return CacheLookup::Miss {
                reason: record.reason.clone(),
            };
        }
        self.validated_hit(identity, &key, &stored, lookup_started)
    }

    fn validated_hit(
        &mut self,
        identity: &DerivedCacheIdentity,
        key: &str,
        stored: &StoredEntry,
        lookup_started: Instant,
    ) -> CacheLookup {
        let artifact = CachedArtifact::fresh(identity, key, stored.bytes.clone());
        if let Err(error) = artifact.lineage.validate() {
            self.entries.remove(key);
            self.stored_bytes = self.stored_bytes.saturating_sub(stored.byte_len);
            let record = self.record_rejection(
                Some(key.to_owned()),
                CacheRejectReason::UnvalidatedIdentity {
                    detail: error.to_string(),
                },
            );
            self.counters.misses = self.counters.misses.saturating_add(1);
            return CacheLookup::Miss {
                reason: record.reason,
            };
        }
        let warm_duration_ms =
            u64::try_from(lookup_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_warm_duration_ms = Some(warm_duration_ms);
        self.counters.hits = self.counters.hits.saturating_add(1);
        CacheLookup::Hit(artifact)
    }

    /// Publishes one fresh derivation under its identity.
    ///
    /// The publish validates the closure, authenticates producer and root,
    /// admits the schema revision, verifies the derived bytes against the
    /// declared content digest, and refuses a narrower subset overwrite of a
    /// broader valid union entry without declared replacement semantics.
    pub fn publish(
        &mut self,
        identity: &DerivedCacheIdentity,
        trust: &TrustPolicy,
        fresh: FreshDerivation,
    ) -> Result<CachedArtifact, CacheStoreError> {
        identity
            .validate()
            .map_err(|error| CacheStoreError::InvalidIdentity(error.to_string()))?;
        trust
            .authenticate(identity)
            .map_err(|reason| match reason {
                CacheRejectReason::UntrustedProducer => CacheStoreError::UntrustedProducer,
                CacheRejectReason::UntrustedRoot => CacheStoreError::UntrustedRoot,
                other => CacheStoreError::InvalidIdentity(format!("{other:?}")),
            })?;
        if !ADMITTED_SCHEMA_REVISIONS.contains(&identity.schema_revision.as_str()) {
            return Err(CacheStoreError::UnsupportedSchema(
                identity.schema_revision.clone(),
            ));
        }
        let key = identity
            .digest()
            .map_err(|error| CacheStoreError::InvalidIdentity(error.to_string()))?;
        let actual = crate::sha256_of(&fresh.bytes);
        if actual != identity.content_digest {
            let record_reason = CacheRejectReason::ContentMismatch {
                expected: identity.content_digest.clone(),
                actual: actual.clone(),
            };
            self.record_rejection(Some(key), record_reason);
            return Err(CacheStoreError::ContentMismatch {
                expected: identity.content_digest.clone(),
                actual,
            });
        }
        let byte_len = u64::try_from(fresh.bytes.len()).unwrap_or(u64::MAX);
        if byte_len > self.limits.max_bytes {
            let record_reason = CacheRejectReason::EntryTooLarge { byte_len };
            self.record_rejection(Some(key), record_reason);
            return Err(CacheStoreError::EntryTooLarge { byte_len });
        }
        let existing_breadth = self.entries.get(&key).map(|entry| entry.coverage_breadth);
        if let Some(existing_breadth) = existing_breadth
            && existing_breadth > fresh.coverage_breadth
            && !fresh.replacement_declared
        {
            let record_reason = CacheRejectReason::NarrowerUnionWithoutReplacement {
                existing_breadth,
                candidate_breadth: fresh.coverage_breadth,
            };
            self.record_rejection(Some(key), record_reason);
            return Err(CacheStoreError::NarrowerUnionWithoutReplacement {
                existing_breadth,
                candidate_breadth: fresh.coverage_breadth,
            });
        }
        let sequence = self.next_sequence();
        if let Some(existing) = self.entries.remove(&key) {
            self.stored_bytes = self.stored_bytes.saturating_sub(existing.byte_len);
        }
        self.evict_for(byte_len);
        self.stored_bytes = self.stored_bytes.saturating_add(byte_len);
        self.entries.insert(
            key.clone(),
            StoredEntry {
                identity: identity.clone(),
                bytes: fresh.bytes.clone(),
                byte_len,
                coverage_breadth: fresh.coverage_breadth,
                sequence,
            },
        );
        self.counters.stores = self.counters.stores.saturating_add(1);
        Ok(CachedArtifact::fresh(identity, &key, fresh.bytes))
    }

    fn evict_for(&mut self, incoming: u64) {
        while (!self.entries.is_empty()
            && (self.entries.len() >= self.limits.max_entries
                || self.stored_bytes.saturating_add(incoming) > self.limits.max_bytes))
            && let Some(victim) = oldest_key(&self.entries)
        {
            if let Some(removed) = self.entries.remove(&victim) {
                self.stored_bytes = self.stored_bytes.saturating_sub(removed.byte_len);
                self.counters.evictions = self.counters.evictions.saturating_add(1);
            }
        }
    }

    /// Resolves through the cache, falling through to real derivation.
    ///
    /// On a hit the derivation closure never runs and the hit carries
    /// artifact lineage only. On any miss the closure runs the genuine
    /// uncached derivation; a subsequent publish failure is recorded as a
    /// rejection and still returns the freshly derived bytes, so cache
    /// availability is never on the correctness path.
    pub fn resolve_or_derive(
        &mut self,
        identity: &DerivedCacheIdentity,
        trust: &TrustPolicy,
        derive: impl FnOnce() -> FreshDerivation,
    ) -> DerivationOutcome {
        match self.lookup(identity, trust) {
            CacheLookup::Hit(artifact) => DerivationOutcome {
                artifact,
                cached: true,
                rejected: None,
                derive_duration_ms: None,
            },
            CacheLookup::Miss { reason } => {
                let rejected = if reason.is_recorded() {
                    self.rejected.back().cloned()
                } else {
                    None
                };
                let started = Instant::now();
                let fresh = derive();
                let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                self.last_derive_duration_ms = Some(elapsed_ms);
                self.counters.derivations = self.counters.derivations.saturating_add(1);
                match self.publish(identity, trust, fresh.clone()) {
                    Ok(artifact) => DerivationOutcome {
                        artifact,
                        cached: false,
                        rejected,
                        derive_duration_ms: Some(elapsed_ms),
                    },
                    Err(error) => {
                        let key = identity.digest().ok();
                        let record = self.record_rejection(key, store_error_reason(&error));
                        let artifact = CachedArtifact::fresh(
                            identity,
                            record.identity_digest.as_deref().unwrap_or("unkeyed"),
                            fresh.bytes,
                        );
                        DerivationOutcome {
                            artifact,
                            cached: false,
                            rejected: Some(rejected.unwrap_or(record)),
                            derive_duration_ms: Some(elapsed_ms),
                        }
                    }
                }
            }
        }
    }
}

fn oldest_key(entries: &BTreeMap<String, StoredEntry>) -> Option<String> {
    entries
        .iter()
        .min_by_key(|(_, entry)| entry.sequence)
        .map(|(key, _)| key.clone())
}

fn store_error_reason(error: &CacheStoreError) -> CacheRejectReason {
    match error {
        CacheStoreError::InvalidIdentity(detail) => CacheRejectReason::UnvalidatedIdentity {
            detail: detail.clone(),
        },
        CacheStoreError::UntrustedProducer => CacheRejectReason::UntrustedProducer,
        CacheStoreError::UntrustedRoot => CacheRejectReason::UntrustedRoot,
        CacheStoreError::UnsupportedSchema(revision) => CacheRejectReason::UnsupportedSchema {
            revision: revision.clone(),
        },
        CacheStoreError::ContentMismatch { expected, actual } => {
            CacheRejectReason::ContentMismatch {
                expected: expected.clone(),
                actual: actual.clone(),
            }
        }
        CacheStoreError::EntryTooLarge { byte_len } => CacheRejectReason::EntryTooLarge {
            byte_len: *byte_len,
        },
        CacheStoreError::NarrowerUnionWithoutReplacement {
            existing_breadth,
            candidate_breadth,
        } => CacheRejectReason::NarrowerUnionWithoutReplacement {
            existing_breadth: *existing_breadth,
            candidate_breadth: *candidate_breadth,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(label: &str) -> String {
        crate::sha256_of(label.as_bytes())
    }

    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{error:?}"),
        }
    }

    fn identity_for(content: &[u8]) -> DerivedCacheIdentity {
        DerivedCacheIdentity {
            source_digest: digest_of("source-closure"),
            generated_input_digest: digest_of("generated-inputs"),
            toolchain_version: "rustc 1.89.0 (x86_64-pc-windows-msvc)".to_owned(),
            compiler_version: "rustc 1.89.0".to_owned(),
            parser_version: "eliot.instrument.rustc/1.0.0".to_owned(),
            runtime_version: "isolated-process".to_owned(),
            config_digest: digest_of("config-features-environment"),
            producer_id: "producer-a".to_owned(),
            producer_generation: 7,
            root_identity: "cache-root-a".to_owned(),
            root_acl_digest: digest_of("root-acl"),
            root_disposition: RootDisposition::Direct,
            schema_revision: DERIVED_CACHE_SCHEMA_V1.to_owned(),
            content_digest: crate::sha256_of(content),
        }
    }

    fn trust() -> TrustPolicy {
        ok(TrustPolicy::new(
            vec!["producer-a".to_owned()],
            vec!["cache-root-a".to_owned()],
        ))
    }

    fn store() -> DerivedCacheStore {
        DerivedCacheStore::new(CacheLimits::default())
    }

    #[test]
    fn hit_reuses_lineage_and_never_runs_derivation() {
        let bytes = b"derived-artifact-bytes";
        let identity = identity_for(bytes);
        let trust = trust();
        let mut store = store();
        let mut derives = 0usize;
        let first = store.resolve_or_derive(&identity, &trust, || {
            derives += 1;
            FreshDerivation::new(bytes.to_vec(), 4, false)
        });
        assert!(!first.cached);
        assert_eq!(derives, 1);
        assert_eq!(first.artifact.bytes, bytes);
        assert_eq!(first.artifact.lineage.producer_id, "producer-a");
        assert_eq!(first.artifact.lineage.producer_generation, 7);
        assert_eq!(first.artifact.lineage.root_identity, "cache-root-a");
        assert_eq!(
            first.artifact.lineage.schema_revision,
            DERIVED_CACHE_SCHEMA_V1
        );

        let second = store.resolve_or_derive(&identity, &trust, || {
            derives += 1;
            FreshDerivation::new(b"stale-bytes".to_vec(), 4, false)
        });
        assert!(second.cached);
        assert_eq!(derives, 1);
        assert_eq!(second.artifact.bytes, bytes);
        assert_eq!(second.artifact.lineage, first.artifact.lineage);
        assert_eq!(store.counters().hits, 1);
        assert_eq!(store.counters().hit_rate(), Some(0.5));
    }

    #[test]
    fn any_closure_change_forces_miss_and_fresh_derivation() {
        let bytes = b"closure-bytes";
        let base = identity_for(bytes);
        let trust = trust();
        let mut store = store();
        ok(store.publish(
            &base,
            &trust,
            FreshDerivation::new(bytes.to_vec(), 2, false),
        ));

        let mut variants = vec![
            ("source", {
                let mut id = base.clone();
                id.source_digest = digest_of("other-source-closure");
                id.content_digest = crate::sha256_of(b"variant-bytes");
                id
            }),
            ("toolchain", {
                let mut id = base.clone();
                id.toolchain_version = "rustc 1.90.0".to_owned();
                id.content_digest = crate::sha256_of(b"variant-bytes");
                id
            }),
            ("producer-generation", {
                let mut id = base.clone();
                id.producer_generation = 8;
                id.content_digest = crate::sha256_of(b"variant-bytes");
                id
            }),
            ("root-disposition", {
                let mut id = base.clone();
                id.root_disposition = RootDisposition::Symlink;
                id.content_digest = crate::sha256_of(b"variant-bytes");
                id
            }),
            ("schema", {
                let mut id = base.clone();
                id.schema_revision = "eliot.derived-cache/v9".to_owned();
                id.content_digest = crate::sha256_of(b"variant-bytes");
                id
            }),
        ];
        for (name, variant) in variants.drain(..) {
            let mut ran = false;
            let outcome = store.resolve_or_derive(&variant, &trust, || {
                ran = true;
                FreshDerivation::new(b"variant-bytes".to_vec(), 2, true)
            });
            assert!(!outcome.cached, "variant {name} must miss");
            assert!(ran, "variant {name} must run uncached derivation");
            assert_eq!(outcome.artifact.bytes, b"variant-bytes");
        }
        assert!(store.counters().misses >= 5);
    }

    #[test]
    fn invalid_cache_is_miss_not_failure_and_preserves_valid_entries() {
        let good_bytes = b"good-entry";
        let good = identity_for(good_bytes);
        let trust = trust();
        let mut store = store();
        ok(store.publish(
            &good,
            &trust,
            FreshDerivation::new(good_bytes.to_vec(), 2, false),
        ));

        let mut untrusted = good.clone();
        untrusted.producer_id = "producer-evil".to_owned();
        let mut ran = false;
        let outcome = store.resolve_or_derive(&untrusted, &trust, || {
            ran = true;
            FreshDerivation::new(b"fresh".to_vec(), 1, false)
        });
        assert!(!outcome.cached);
        assert!(ran);
        assert_eq!(outcome.artifact.bytes, b"fresh");
        assert!(matches!(
            outcome.rejected,
            Some(RejectedCacheRecord {
                reason: CacheRejectReason::UntrustedProducer,
                ..
            })
        ));

        let mut untrusted_root = good.clone();
        untrusted_root.root_identity = "cache-root-evil".to_owned();
        let outcome = store.resolve_or_derive(&untrusted_root, &trust, || {
            FreshDerivation::new(b"fresh".to_vec(), 1, false)
        });
        assert!(!outcome.cached);
        assert!(matches!(
            outcome.rejected,
            Some(RejectedCacheRecord {
                reason: CacheRejectReason::UntrustedRoot,
                ..
            })
        ));

        let mut corrupt = good.clone();
        corrupt.generated_input_digest = digest_of("other-generated-inputs");
        corrupt.content_digest = crate::sha256_of(b"corrupt-bytes");
        let key = ok(corrupt.digest());
        store.entries.insert(
            key.clone(),
            StoredEntry {
                identity: corrupt.clone(),
                bytes: b"tampered".to_vec(),
                byte_len: 8,
                coverage_breadth: 1,
                sequence: 99,
            },
        );
        store.stored_bytes = store.stored_bytes.saturating_add(8);
        let outcome = store.resolve_or_derive(&corrupt, &trust, || {
            FreshDerivation::new(b"corrupt-bytes".to_vec(), 1, true)
        });
        assert!(!outcome.cached);
        assert!(matches!(
            outcome.rejected,
            Some(RejectedCacheRecord {
                reason: CacheRejectReason::ContentCorrupt { .. },
                ..
            })
        ));

        match store.lookup(&good, &trust) {
            CacheLookup::Hit(artifact) => assert_eq!(artifact.bytes, good_bytes),
            CacheLookup::Miss { .. } => unreachable!(),
        }
        assert!(store.counters().rejections >= 3);
    }

    #[test]
    fn narrower_subset_cannot_overwrite_broader_union() {
        let bytes = b"union-bytes";
        let identity = identity_for(bytes);
        let trust = trust();
        let mut store = store();
        ok(store.publish(
            &identity,
            &trust,
            FreshDerivation::new(bytes.to_vec(), 10, false),
        ));

        let refused = store.publish(
            &identity,
            &trust,
            FreshDerivation::new(bytes.to_vec(), 3, false),
        );
        assert!(matches!(
            refused,
            Err(CacheStoreError::NarrowerUnionWithoutReplacement {
                existing_breadth: 10,
                candidate_breadth: 3,
            })
        ));
        match store.lookup(&identity, &trust) {
            CacheLookup::Hit(artifact) => assert_eq!(artifact.bytes, bytes),
            CacheLookup::Miss { .. } => unreachable!(),
        }

        ok(store.publish(
            &identity,
            &trust,
            FreshDerivation::new(bytes.to_vec(), 3, true),
        ));
    }

    #[test]
    fn unavailable_cache_never_fails_correctness() {
        let bytes = b"correct-bytes";
        let identity = identity_for(bytes);
        let trust = trust();
        let mut store = store();

        let cold = store.resolve_or_derive(&identity, &trust, || {
            FreshDerivation::new(bytes.to_vec(), 1, false)
        });
        assert!(!cold.cached);
        assert_eq!(cold.artifact.bytes, bytes);
        assert!(cold.derive_duration_ms.is_some());

        let mut bad = identity_for(b"declared-bytes");
        bad.source_digest = digest_of("other-source-for-publish-failure");
        let wrong = FreshDerivation::new(b"wrong-bytes".to_vec(), 1, true);
        let outcome = store.resolve_or_derive(&bad, &trust, || wrong.clone());
        assert!(!outcome.cached);
        assert_eq!(outcome.artifact.bytes, b"wrong-bytes");
        assert!(outcome.rejected.is_some());
    }
}
