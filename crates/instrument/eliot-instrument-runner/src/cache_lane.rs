//! Governed derived-cache lane: registry-bound reuse enforcement (issue #1898).
//!
//! [`CacheLane`] is the dedicated caller of the I2.22 derived-cache
//! enforcement owned by `eliot-build-test-graph`. It bridges the existing
//! instrument owner types ([`RegistryEntry`], [`ResolvedExecutableIdentity`])
//! plus caller-attested closure digests into one [`DerivedCacheIdentity`]
//! and consults the store before running derivation:
//!
//! ```text
//! hit  -> derivation is skipped; the hit carries artifact lineage only;
//! miss -> the real uncached derivation runs; its output is published;
//! invalid/unreadable/untrusted/mismatched -> miss, never a failure.
//! ```
//!
//! A hit never carries a test or verifier verdict: [`CachedArtifact`] has no
//! verdict field, so reuse cannot supply a previous candidate's verdict and
//! every candidate still verifies its own derivation.

use eliot_build_test_graph::{
    ArtifactLineage, CacheCounters, CacheLookup, CacheStoreError, CachedArtifact,
    DerivedCacheIdentity, DerivedCacheStore, FreshDerivation, RejectedCacheRecord, RootDisposition,
    TrustPolicy,
};
use thiserror::Error;

use crate::registry::{RegistryEntry, ResolvedExecutableIdentity};

/// Caller-attested closure elements the registry does not own.
///
/// The registry binds adapter, executable, toolchain family, environment
/// class, and fingerprints; the composition root attests the exact digests,
/// producer, cache root, schema revision, and content digest for the
/// derivation it is about to run or reuse. `config_digest` must cover
/// configuration, features (including the admitted profile), and environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheLaneAttestations {
    /// Digest over the exact source closure.
    pub source_digest: String,
    /// Digest over generated inputs (build scripts, proc macros, codegen).
    pub generated_input_digest: String,
    /// Fingerprint digest over configuration, features, and environment.
    pub config_digest: String,
    /// Producer identity admitted to write the entry.
    pub producer_id: String,
    /// Producer generation that derived, or will derive, the entry.
    pub producer_generation: u64,
    /// Cache-root identity holding the entry.
    pub root_identity: String,
    /// Digest over the cache-root ACL observed at derivation time.
    pub root_acl_digest: String,
    /// Reparse/symlink disposition of the cache root.
    pub root_disposition: RootDisposition,
    /// Format/schema revision of the artifact bytes.
    pub schema_revision: String,
    /// Integrity digest the artifact bytes must reproduce.
    pub content_digest: String,
}

/// Failures building a cache identity in the lane.
///
/// An identity failure bypasses the cache and still runs the real uncached
/// derivation ([`LaneOutcome::Derived`] with `cache_bypass` set): it is
/// never a correctness failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CacheLaneError {
    /// No machine-derived executable observation was supplied, so the
    /// compiler version element of the closure cannot be established.
    #[error("cache identity requires a machine-derived executable observation")]
    UnobservedExecutable,
    /// The observed tool version is missing, so the compiler version
    /// element of the closure cannot be established.
    #[error("cache identity requires an observed tool version")]
    UnobservedToolVersion,
    /// The assembled closure failed validation.
    #[error("cache identity is invalid: {0}")]
    InvalidIdentity(String),
}

/// Outcome of one lane consultation with fallthrough derivation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaneOutcome {
    /// A verified entry was reused: derivation was skipped, lineage only.
    Reused {
        /// Reused artifact: lineage plus bytes, never verdicts.
        artifact: CachedArtifact,
    },
    /// The real uncached derivation ran (cache miss or bypass).
    Derived {
        /// Freshly derived artifact.
        artifact: CachedArtifact,
        /// Rejection recorded while consulting the cache, if any.
        rejected: Option<RejectedCacheRecord>,
        /// Set when the cache could not be consulted at all; derivation
        /// still ran, so correctness never depended on the cache.
        cache_bypass: Option<CacheLaneError>,
    },
}

/// Dedicated caller binding registry resolution to derived-cache reuse.
///
/// The lane holds the enforcement store and the trust policy supplied by
/// the composition root. It never launches a process, admits work, or
/// decides verification; it only decides reuse versus real derivation.
pub struct CacheLane {
    store: DerivedCacheStore,
    trust: TrustPolicy,
}

impl CacheLane {
    /// Creates a lane over an explicit store and trust policy.
    #[must_use]
    pub const fn new(store: DerivedCacheStore, trust: TrustPolicy) -> Self {
        Self { store, trust }
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

    /// Builds the exact closure identity for one resolved instrument.
    ///
    /// Toolchain, parser, and runtime elements come from the registry entry
    /// and the machine-derived observation; digests, producer, root, schema,
    /// and content come from caller attestations. A missing observation or
    /// tool version fails closed with [`CacheLaneError`].
    pub fn identity_for(
        entry: &RegistryEntry,
        resolved: Option<&ResolvedExecutableIdentity>,
        attest: &CacheLaneAttestations,
    ) -> Result<DerivedCacheIdentity, CacheLaneError> {
        let Some(observation) = resolved else {
            return Err(CacheLaneError::UnobservedExecutable);
        };
        let Some(compiler_version) = observation.tool_version.clone() else {
            return Err(CacheLaneError::UnobservedToolVersion);
        };
        let identity = DerivedCacheIdentity {
            source_digest: attest.source_digest.clone(),
            generated_input_digest: attest.generated_input_digest.clone(),
            toolchain_version: entry.toolchain.clone(),
            compiler_version,
            parser_version: entry.parser.as_str().to_owned(),
            runtime_version: entry.environment_class.clone(),
            config_digest: attest.config_digest.clone(),
            producer_id: attest.producer_id.clone(),
            producer_generation: attest.producer_generation,
            root_identity: attest.root_identity.clone(),
            root_acl_digest: attest.root_acl_digest.clone(),
            root_disposition: attest.root_disposition,
            schema_revision: attest.schema_revision.clone(),
            content_digest: attest.content_digest.clone(),
        };
        identity
            .validate()
            .map_err(|error| CacheLaneError::InvalidIdentity(error.to_string()))?;
        Ok(identity)
    }

    /// Consults the cache for a prebuilt identity without deriving anything.
    ///
    /// This is the pre-execution check of the two-phase production shape
    /// (`lookup` → run the real derivation on a miss → [`CacheLane::publish_identity`]):
    /// asynchronous composition roots consult the lane before spawning work
    /// and publish the collected evidence afterwards. Any miss means the
    /// caller must run the genuine uncached derivation.
    pub fn lookup_identity(&mut self, identity: &DerivedCacheIdentity) -> CacheLookup {
        self.store.lookup(identity, &self.trust)
    }

    /// Publishes one fresh derivation under a prebuilt identity.
    ///
    /// This is the post-execution step of the two-phase production shape:
    /// the caller ran the real derivation (usually after a
    /// [`CacheLane::lookup_identity`] miss) and hands over the collected
    /// bytes. A publish failure is returned typed and never fails the
    /// derivation the bytes came from.
    ///
    /// # Errors
    ///
    /// Returns [`CacheStoreError`] when the identity is invalid, untrusted,
    /// schema-unsupported, content-mismatched, oversized, or a narrower
    /// subset overwrite without declared replacement semantics.
    pub fn publish_identity(
        &mut self,
        identity: &DerivedCacheIdentity,
        fresh: FreshDerivation,
    ) -> Result<CachedArtifact, CacheStoreError> {
        self.store.publish(identity, &self.trust, fresh)
    }

    /// Reuses a verified entry or runs the real uncached derivation.
    ///
    /// The `derive` closure is the genuine derivation path (the build, test,
    /// or verifier execution producing artifact bytes). It runs if and only
    /// if no verified entry exists; a hit skips it entirely. Publish
    /// failures after a miss are recorded as rejections and still return
    /// the freshly derived bytes.
    pub fn reuse_or_derive(
        &mut self,
        entry: &RegistryEntry,
        resolved: Option<&ResolvedExecutableIdentity>,
        attest: &CacheLaneAttestations,
        derive: impl FnOnce() -> FreshDerivation,
    ) -> LaneOutcome {
        let identity = match Self::identity_for(entry, resolved, attest) {
            Ok(identity) => identity,
            Err(error) => {
                let fresh = derive();
                return LaneOutcome::Derived {
                    artifact: CachedArtifact {
                        lineage: ArtifactLineage {
                            producer_id: attest.producer_id.clone(),
                            producer_generation: attest.producer_generation,
                            root_identity: attest.root_identity.clone(),
                            schema_revision: attest.schema_revision.clone(),
                            identity_digest: "unkeyed".to_owned(),
                            content_digest: attest.content_digest.clone(),
                        },
                        bytes: fresh.bytes,
                    },
                    rejected: None,
                    cache_bypass: Some(error),
                };
            }
        };
        match self.store.lookup(&identity, &self.trust) {
            CacheLookup::Hit(artifact) => LaneOutcome::Reused { artifact },
            CacheLookup::Miss { reason } => {
                let rejected = if reason.is_recorded() {
                    self.store.rejected().pop()
                } else {
                    None
                };
                let fresh = derive();
                if let Ok(artifact) = self.store.publish(&identity, &self.trust, fresh.clone()) {
                    LaneOutcome::Derived {
                        artifact,
                        rejected,
                        cache_bypass: None,
                    }
                } else {
                    let latest = self.store.rejected().pop();
                    let key = identity.digest().ok();
                    let artifact = CachedArtifact::fresh(
                        &identity,
                        key.as_deref().unwrap_or("unkeyed"),
                        fresh.bytes,
                    );
                    LaneOutcome::Derived {
                        artifact,
                        rejected: latest.or(rejected),
                        cache_bypass: None,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_build_test_graph::{CacheLimits, CacheRejectReason};
    use eliot_contracts::{
        ClockReading, ContractId, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        SourceId, StateFence,
    };
    use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
    use eliot_instrument_rustc::RUSTC_INSTRUMENT;
    use std::num::NonZeroU64;

    use crate::registry::{InvalidationSet, ProviderRegistry};

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn unreachable_value<T>(result: Result<T, impl std::fmt::Debug>) -> T {
        match result {
            Ok(value) => value,
            Err(_) => unreachable!(),
        }
    }

    fn eliot_sha256(bytes: &[u8]) -> String {
        eliot_contracts::sha256_hex(bytes)
    }

    fn test_invocation() -> InstrumentInvocation {
        let lineage = unreachable_value(EpochLineageId::new(TEST_LINEAGE_A));
        let epoch = unreachable_value(EpochId::new(
            lineage,
            NonZeroU64::new(1).unwrap_or_else(|| unreachable!()),
        ));
        let clock = ClockReading {
            valid_time_ms: Some(10),
            known_time_ms: Some(11),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        };
        InstrumentInvocation {
            request: RequestMetadata {
                request_id: unreachable_value(RequestId::new("instrument-request-1")),
                session_id: None,
                task_id: None,
                product_id: unreachable_value(ProductId::new("product-1")),
                source_id: unreachable_value(SourceId::new("source-1")),
                state_fence: StateFence::new(epoch, eliot_contracts::ResourceGeneration::genesis()),
                clock,
            },
            instrument: unreachable_value(ContractId::new(RUSTC_INSTRUMENT)),
            kind: InstrumentKind::Build,
            profile: "dev-fast".to_owned(),
            target: "worktree:a04".to_owned(),
            arguments: vec!["--crate-name".to_owned(), "foo".to_owned()],
            input_artifacts: Vec::new(),
            declared_scope: "workspace".to_owned(),
            requested_at: clock,
        }
    }

    fn test_entry() -> RegistryEntry {
        let fingerprints = InvalidationSet {
            source: "source".to_owned(),
            lock: "lock".to_owned(),
            toolchain: "toolchain".to_owned(),
            env: "env".to_owned(),
            exe: "exe".to_owned(),
            profile: "profile".to_owned(),
            parser: "parser".to_owned(),
        };
        let registry = unreachable_value(ProviderRegistry::ready(
            7,
            "normative".to_owned(),
            &fingerprints,
        ));
        match registry.resolve(&test_invocation()) {
            Ok(entry) => entry.clone(),
            Err(_) => unreachable!(),
        }
    }

    fn observation() -> ResolvedExecutableIdentity {
        unreachable_value(ResolvedExecutableIdentity::new(
            RUSTC_INSTRUMENT,
            "/usr/bin/rustc".to_owned(),
            "a".repeat(64),
            Some("rustc 1.89.0".to_owned()),
            "b".repeat(64),
            vec!["--crate-name".to_owned(), "foo".to_owned()],
        ))
    }

    fn attestations(content: &[u8]) -> CacheLaneAttestations {
        CacheLaneAttestations {
            source_digest: eliot_sha256(b"lane-source-closure"),
            generated_input_digest: eliot_sha256(b"lane-generated-inputs"),
            config_digest: eliot_sha256(b"lane-config-features-env"),
            producer_id: "lane-producer".to_owned(),
            producer_generation: 3,
            root_identity: "lane-root".to_owned(),
            root_acl_digest: eliot_sha256(b"lane-root-acl"),
            root_disposition: RootDisposition::Direct,
            schema_revision: eliot_build_test_graph::DERIVED_CACHE_SCHEMA_V1.to_owned(),
            content_digest: eliot_sha256(content),
        }
    }

    fn lane() -> CacheLane {
        let trust = unreachable_value(TrustPolicy::new(
            vec!["lane-producer".to_owned()],
            vec!["lane-root".to_owned()],
        ));
        CacheLane::new(DerivedCacheStore::new(CacheLimits::default()), trust)
    }

    #[test]
    fn lane_miss_runs_uncached_derivation_then_hit_skips_it() {
        let entry = test_entry();
        let resolved = observation();
        let bytes = b"lane-derived-bytes";
        let attest = attestations(bytes);
        let mut lane = lane();
        let mut derives = 0usize;

        let first = lane.reuse_or_derive(&entry, Some(&resolved), &attest, || {
            derives += 1;
            FreshDerivation::new(bytes.to_vec(), 2, false)
        });
        let LaneOutcome::Derived {
            artifact,
            rejected,
            cache_bypass,
        } = first
        else {
            unreachable!()
        };
        assert_eq!(derives, 1);
        assert_eq!(artifact.bytes, bytes);
        assert_eq!(artifact.lineage.producer_id, "lane-producer");
        assert_eq!(artifact.lineage.producer_generation, 3);
        assert_eq!(artifact.lineage.root_identity, "lane-root");
        assert!(rejected.is_none());
        assert!(cache_bypass.is_none());

        let second = lane.reuse_or_derive(&entry, Some(&resolved), &attest, || {
            derives += 1;
            FreshDerivation::new(b"stale-bytes".to_vec(), 2, false)
        });
        let LaneOutcome::Reused { artifact } = second else {
            unreachable!()
        };
        assert_eq!(derives, 1);
        assert_eq!(artifact.bytes, bytes);
        assert_eq!(lane.counters().hits, 1);
        assert_eq!(lane.counters().misses, 1);
    }

    #[test]
    fn lane_toolchain_change_forces_miss_and_fresh_derivation() {
        let entry = test_entry();
        let resolved = observation();
        let bytes = b"lane-toolchain-bytes";
        let attest = attestations(bytes);
        let mut lane = lane();
        let mut derives = 0usize;

        let first = lane.reuse_or_derive(&entry, Some(&resolved), &attest, || {
            derives += 1;
            FreshDerivation::new(bytes.to_vec(), 2, false)
        });
        assert!(matches!(first, LaneOutcome::Derived { .. }));

        let mut changed = resolved.clone();
        changed.tool_version = Some("rustc 1.90.0".to_owned());
        let second = lane.reuse_or_derive(&entry, Some(&changed), &attest, || {
            derives += 1;
            FreshDerivation::new(b"rebuilt-bytes".to_vec(), 2, true)
        });
        let LaneOutcome::Derived { artifact, .. } = second else {
            unreachable!()
        };
        assert_eq!(derives, 2);
        assert_eq!(artifact.bytes, b"rebuilt-bytes");
    }

    #[test]
    fn lane_records_rejection_and_preserves_valid_entries() {
        let entry = test_entry();
        let resolved = observation();
        let bytes = b"lane-good-bytes";
        let attest = attestations(bytes);
        let mut lane = lane();

        let first = lane.reuse_or_derive(&entry, Some(&resolved), &attest, || {
            FreshDerivation::new(bytes.to_vec(), 2, false)
        });
        assert!(matches!(first, LaneOutcome::Derived { .. }));

        let mut evil = attest.clone();
        evil.producer_id = "untrusted-producer".to_owned();
        let mut ran = false;
        let outcome = lane.reuse_or_derive(&entry, Some(&resolved), &evil, || {
            ran = true;
            FreshDerivation::new(b"fresh-bytes".to_vec(), 1, false)
        });
        let LaneOutcome::Derived {
            artifact, rejected, ..
        } = outcome
        else {
            unreachable!()
        };
        assert!(ran);
        assert_eq!(artifact.bytes, b"fresh-bytes");
        assert!(matches!(
            rejected,
            Some(RejectedCacheRecord {
                reason: CacheRejectReason::UntrustedProducer,
                ..
            })
        ));

        let again = lane.reuse_or_derive(&entry, Some(&resolved), &attest, || {
            FreshDerivation::new(b"stale-bytes".to_vec(), 2, false)
        });
        let LaneOutcome::Reused { artifact } = again else {
            unreachable!()
        };
        assert_eq!(artifact.bytes, bytes);
        assert!(!lane.rejected().is_empty());
    }
}
