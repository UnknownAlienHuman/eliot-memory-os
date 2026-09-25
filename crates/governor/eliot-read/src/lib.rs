//! G-06 Governor read/query contracts and named-read facade.
//!
//! DISPOSITION (#1144, WIRE): this crate is the declared Governor read owner.
//! It is a stateless projection over the store-neutral named read port
//! ([`CanonicalReadClient`]): it owns no cache, no freshness state, and no
//! second consistency algorithm. Every read binds the caller request identity,
//! scope, consistency, dependency revisions, current [`StateFence`], and exact
//! source/evidence handles, and returns revision heads with provenance
//! disposition so callers can revalidate. Real consumers: `eliot-governor`
//! (`ReadApi` for context/input reconstruction) and `eliotd` (`LocalReadPort`
//! for `eliot.query` / `eliot.packet` answers).
//!
//! Requests carry explicit intent, scope, consistency and fence
//! dependencies. The facade never accepts raw database query text, writes
//! canonical state, or treats a payload as proof merely because it was read.
//! Intent dimensions are closed enums, named parameters are bounded scalar
//! selectors, and store failures keep their exact typed identity. Store
//! payloads remain opaque; callers receive their exact payload together
//! with revision and provenance disposition so a later layer can apply the
//! appropriate semantic contract.
//!
//! # Owner inventory (W1)
//!
//! Owned mutable state: **none**. [`ReadService`] holds exactly one field, the
//! caller-owned store client; every read re-dispatches to that client under the
//! caller fence, so no cache, freshness state, or second consistency algorithm
//! exists in this package (ARCH-MOD-03 explicit statelessness).
//!
//! ```text
//! public API:        ReadApi, LocalReadPort, ReadService,
//!                    contract_identity, CONTRACT_NAME, CONTRACT_VERSION,
//!                    context_reconstruction_operations,
//!                    ReadOutcome, ReadPrincipal, ReadSchemaIdentity,
//!                    ReadSourceIdentity, ReadCoverage, ReadOrderingBinding,
//!                    ReadIdentity, ReadInvalidationSet, BoundRead,
//!                    QueryMode, TimeScope, BranchEnvironmentScope,
//!                    FreshnessPolicy, RequiredAssurance, QueryIntent,
//!                    NamedParameters, EliotResourceUri, ProvenanceHandle,
//!                    ProvenanceDisposition, ReadProvenance,
//!                    StateRequest, QueryRequest, ResourceRequest,
//!                    CurrentStateView, QueryResult, ResourceContent,
//!                    ReadError, StoreReadFailure;
//! store dependency:   CanonicalReadClient (read-only), the Store operation
//!                    catalogue (generated_operation_manifests,
//!                    activated_read_operations, declared_read_parameters,
//!                    project_parameter_schema, parameter_schema_digest) and
//!                    the Store-owned experience page coverage statement
//!                    (ExperienceRangePage). No SurrealDB SDK, no credentials,
//!                    no write capability, no raw query text;
//! serialization:      every public type is `deny_unknown_fields` JSON with
//!                    closed enum dimensions; intents reject unknown future
//!                    prose instead of widening the read;
//! tests:             crates/governor/eliot-read/tests/read_owner_proof.rs,
//!                    crates/governor/eliot-read/tests/context_reconstruction.rs,
//!                    in-crate `evidence_pack_read_tests`.
//! ```
//!
//! # Comparison with the current read owner, Store read model and runtime
//! # status consumers (W2)
//!
//! ```text
//! semantic read owner:      this crate (G-06). The Governor read *policy*
//!                            (intent, coverage, provenance, freshness refusal)
//!                            lives here; it is the only place that decides
//!                            whether a payload may be called current.
//! physical data access:      CanonicalReadClient only. `bins/eliotd` supplies
//!                            KernelContextReadClient (Kernel transport) and
//!                            the store adapters supply the memory/Surreal
//!                            handlers. Neither owns a read decision.
//! Store read model:          `eliot_store_api::NamedReadRequest` /
//!                            `NamedReadResponse` / `ReadConsistency` /
//!                            `RevisionHead` / `OrderingHead` /
//!                            `ScopeRevisionView` and the generated operation
//!                            catalogue. This crate consumes those identities
//!                            read-only and never re-declares them.
//! runtime-status consumers:  `crates/governor/eliot-governor/src/
//!                            context_inputs.rs` retains seven role reads with
//!                            `ProjectionState` dispositions; `bins/eliotd`
//!                            retains one bounded evidence read per admitted
//!                            `eliot.query` pair. Both consume the resolved
//!                            [`ReadIdentity`] instead of re-deriving freshness.
//! ```
//!
//! # Retained-read binding (W5, A3)
//!
//! [`ReadIdentity`] is the exact closure every retained read is bound to:
//! principal (derived only from the caller's validated [`RequestMetadata`]),
//! request identity, scope, current [`StateFence`], consistency mode, the
//! declared dependency revisions, the observed revision heads, the declared
//! order-head dependency ([`ReadOrderingBinding`]), the resolved source
//! ([`ReadSourceIdentity`]) and projection schema ([`ReadSchemaIdentity`]),
//! the coverage identity ([`ReadCoverage`]) and the exact invalidation
//! conditions ([`ReadInvalidationSet`], I5.20). The order-head dependency is a
//! required field on every request: omitting it is a compile error, never a
//! default, and a declared head bound to another fence is refused rather than
//! carried as a live dependency. No value in the closure is time-derived, and
//! no completeness percentage, TTL, or eviction rule is invented: the closure
//! is exactly what the caller declared plus what the Store catalogue and the
//! observed heads prove.
//!
//! # Read outcomes (A5)
//!
//! [`ReadOutcome`] is the closed observation vocabulary of this owner. Only
//! `Current` is reachable by a successful read, so an empty in-memory payload
//! can never become a successful empty or current result: a payload that
//! carries no observation of the bound identity is `Unknown`, an operation with
//! no activated Store handler is `NotRunning`, and a source-declared truncated
//! coverage statement is `Partial`. `Unavailable`, `Stale` and `Conflicted`
//! keep their existing typed [`ReadError`] variants so the exact store identity
//! survives; the three owner-level states travel as
//! [`ReadError::Outcome`]. No failure collapses into a string, a generic code,
//! or another state.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{
    ContractIdentity, ContractVersion, ProductId, RequestId, RequestMetadata, SessionId, SourceId,
    StateFence, TaskId, contract_identity as make_contract_identity,
};
use eliot_store_api::{
    CanonicalReadClient, ExperienceRangePage, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, OrderingHead, ReadConsistency, RevisionHead, RevisionKey, ScopeId,
    StoreError, activated_read_operations, declared_read_parameters, named_read_operation_name,
    parameter_schema_digest, project_parameter_schema,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Stable wire name for the Governor read contract.
pub const CONTRACT_NAME: &str = "eliot.governor.read";
/// Current wire revision for the Governor read contract.
///
/// `3.0.0` adds the retained-read identity closure ([`ReadIdentity`]), the
/// caller-declared order-head dependency ([`ReadOrderingBinding`]), the
/// owner-resolved coverage identity ([`ReadCoverage`]) and the closed read
/// outcome vocabulary ([`ReadOutcome`]).
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(3, 0, 0);

/// Closed semantic query modes from the public ELIOT query surface.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryMode {
    /// Resolve the currently supported position under the supplied fence.
    CurrentPosition,
    /// Reconstruct a bounded historical position; never silently current.
    HistoricalReconstruction,
    /// Follow exact source, evidence and decision lineage.
    Provenance,
    /// Return navigation candidates that are not evidence or proof.
    Navigation,
    /// Read verifier-oriented evidence and run lineage.
    Verification,
    /// Read a bounded change-impact projection.
    ChangeImpact,
    /// Reconstruct a bounded context/input view.
    ContextReconstruction,
}

/// Closed time-window semantics for a broad query: the window is always
/// bounded by the request fence, never wall-clock inference.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeScope {
    /// Bounded closure under the exact declared fence.
    DeclaredFence,
    /// Bounded captured-evidence window under the declared fence.
    EvidenceWindow,
    /// Bounded projection-inputs window under the declared fence.
    ProjectionWindow,
    /// Bounded task window under the declared fence.
    TaskWindow,
}

/// Closed branch/environment scope for a broad query.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchEnvironmentScope {
    /// Exactly the request scope and fence, nothing wider.
    RequestScope,
    /// The local Governor branch and environment serving the read.
    LocalEnvironment,
}

/// Closed freshness behavior for a broad query. Freshness is never inferred:
/// each variant names the exact revision/fence evidence the read enforces.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessPolicy {
    /// Exactly the captured records, no newer or older substitution.
    ExactCapturedRecords,
    /// Exact-fence reads with declared dependency revisions.
    ExactFence,
    /// Exactly the projection inputs, nothing wider.
    ProjectionInputsOnly,
    /// Exactly the admitted generation, never a stale generation as current.
    AdmittedGeneration,
}

/// Closed assurance/proof behavior for a broad query. A read never admits,
/// proves, or finishes work; it only names the allowed read-only use.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredAssurance {
    /// Verifier-oriented evidence read.
    VerifierEvidence,
    /// Input reconstruction read; no admission or proof.
    ReconstructionInputs,
    /// Input reconstruction only; explicitly no admission, proof, or finish.
    InputReconstructionOnly,
}

/// Explicit assurance semantics for a broad query.
///
/// Every dimension is a closed enum: free-text intent prose is not a selector
/// and never crosses this boundary. Agent-facing free text stays at the
/// calling surface; only these typed dimensions enter the Governor facade.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryIntent {
    /// Semantic query mode.
    pub mode: QueryMode,
    /// Exact time window, always bounded by the request fence.
    pub time_scope: TimeScope,
    /// Branch and environment scope.
    pub branch_environment_scope: BranchEnvironmentScope,
    /// Required freshness behavior.
    pub freshness_policy: FreshnessPolicy,
    /// Required assurance/proof behavior.
    pub required_assurance: RequiredAssurance,
}

/// Immutable exact resource URI used for expansion reads.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EliotResourceUri(String);

impl EliotResourceUri {
    /// Creates an exact URI without resolving or dereferencing it.
    pub fn new(value: impl Into<String>) -> Result<Self, ReadError> {
        let value = value.into();
        text(&value, "resource_uri")?;
        if value.chars().any(char::is_whitespace) || !value.contains("://") {
            return Err(ReadError::InvalidResourceUri);
        }
        if value.len() > 2048 {
            return Err(ReadError::InvalidField {
                field: "resource_uri".to_owned(),
                reason: "exceeds 2048 bytes".to_owned(),
            });
        }
        Ok(Self(value))
    }

    /// Returns the exact URI string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EliotResourceUri {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Exact provenance/evidence handle supplied by an owning read model.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProvenanceHandle(String);

impl ProvenanceHandle {
    /// Creates a non-blank immutable handle.
    pub fn new(value: impl Into<String>) -> Result<Self, ReadError> {
        let value = value.into();
        text(&value, "provenance_handle")?;
        if value.len() > 4096 {
            return Err(ReadError::InvalidField {
                field: "provenance_handle".to_owned(),
                reason: "exceeds 4096 bytes".to_owned(),
            });
        }
        Ok(Self(value))
    }

    /// Returns the exact handle string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProvenanceHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Whether result lineage is present and how it may be used.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceDisposition {
    /// The caller supplied exact source/evidence handles for this read.
    Declared,
    /// No exact handle was supplied; the payload remains read-only context.
    Unavailable,
}

/// Result lineage attached to every read response.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadProvenance {
    /// Exact handles, never display labels or guessed IDs.
    pub handles: Vec<ProvenanceHandle>,
    /// Whether those handles were declared by the read caller.
    pub disposition: ProvenanceDisposition,
}

impl ReadProvenance {
    fn from_handles(handles: &[ProvenanceHandle]) -> Result<Self, ReadError> {
        let mut unique = BTreeSet::new();
        for handle in handles {
            if !unique.insert(handle.clone()) {
                return Err(ReadError::DuplicateField("provenance_handles".to_owned()));
            }
        }
        Ok(Self {
            handles: handles.to_vec(),
            disposition: if handles.is_empty() {
                ProvenanceDisposition::Unavailable
            } else {
                ProvenanceDisposition::Declared
            },
        })
    }
}

/// Closed named-operation selectors for one read.
///
/// The transport is the same store-neutral selector map the Store catalogue
/// gates, but this boundary is closed: at most [`Self::MAX_ENTRIES`] entries,
/// non-blank control-free keys bounded to [`Self::MAX_KEY_CHARS`] characters,
/// scalar values only (bounded text, number, boolean — never null, never a
/// nested array/object filter), and the retired top-level selector names
/// (`query`, `exact_resource_uri`) rejected so a pre-wire caller cannot
/// smuggle a free-text selector through the parameter namespace. Per-operation
/// allowed keys stay owned by the Store operation catalogue, which re-gates
/// every request before dispatch.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NamedParameters(BTreeMap<String, Value>);

impl NamedParameters {
    /// Maximum closed selectors carried by one read request.
    pub const MAX_ENTRIES: usize = 32;
    /// Maximum key length in characters.
    pub const MAX_KEY_CHARS: usize = 128;
    /// Maximum text selector length in characters.
    pub const MAX_STRING_CHARS: usize = 8192;

    /// Creates an empty closed selector map.
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Wraps an exact selector map after validating every entry.
    pub fn from_map(map: BTreeMap<String, Value>) -> Result<Self, ReadError> {
        let parameters = Self(map);
        parameters.validate()?;
        Ok(parameters)
    }

    /// Validates every closed selector entry.
    pub fn validate(&self) -> Result<(), ReadError> {
        if self.0.len() > Self::MAX_ENTRIES {
            return Err(ReadError::InvalidField {
                field: "named_parameters".to_owned(),
                reason: "exceeds 32 closed selectors".to_owned(),
            });
        }
        for (name, value) in &self.0 {
            text(name, "named_parameter")?;
            if name.chars().count() > Self::MAX_KEY_CHARS {
                return Err(ReadError::InvalidField {
                    field: "named_parameter".to_owned(),
                    reason: "selector name exceeds 128 characters".to_owned(),
                });
            }
            if name == "query" || name == "exact_resource_uri" {
                return Err(ReadError::DuplicateField("named_parameters".to_owned()));
            }
            match value {
                Value::Null => {
                    return Err(ReadError::InvalidField {
                        field: "named_parameter".to_owned(),
                        reason: "null values are not allowed".to_owned(),
                    });
                }
                Value::String(selector) => {
                    text(selector, "named_parameter")?;
                    if selector.chars().count() > Self::MAX_STRING_CHARS {
                        return Err(ReadError::InvalidField {
                            field: "named_parameter".to_owned(),
                            reason: "text selector exceeds 8192 characters".to_owned(),
                        });
                    }
                }
                Value::Number(_) | Value::Bool(_) => {}
                Value::Array(_) | Value::Object(_) => {
                    return Err(ReadError::InvalidField {
                        field: "named_parameter".to_owned(),
                        reason: "nested filters are not allowed; closed scalar selectors only"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Inserts one exact selector, rejecting collisions and malformed entries.
    pub fn insert(&mut self, key: String, value: Value) -> Result<(), ReadError> {
        if self.0.contains_key(&key) {
            return Err(ReadError::DuplicateField("named_parameters".to_owned()));
        }
        let candidate = Self(BTreeMap::from([(key, value)]));
        candidate.validate()?;
        self.0.extend(candidate.0);
        Ok(())
    }

    /// Inserts one exact text selector owned by the facade itself (for example
    /// the resource URI an expansion read binds). Caller-supplied collisions
    /// fail closed so an exact identity can never be shadowed.
    pub fn insert_exact(&mut self, key: &str, value: &str) -> Result<(), ReadError> {
        self.insert(key.to_owned(), Value::String(value.to_owned()))
    }

    /// Returns the underlying selector map for store-neutral dispatch.
    #[must_use]
    pub fn as_map(&self) -> &BTreeMap<String, Value> {
        &self.0
    }

    /// Consumes the wrapper into the underlying selector map.
    #[must_use]
    pub fn into_inner(self) -> BTreeMap<String, Value> {
        self.0
    }

    /// Returns the number of closed selectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when no selector is bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Closed read observation vocabulary of the Governor read owner.
///
/// The non-current states are the exact I0.5 conformance/evidence
/// observation vocabulary plus its `PARTIAL` coverage state, and they are
/// closed: no other value exists, so a consumer never re-derives the
/// distinction from prose or a message. `Current` is reachable only by a
/// successful read — every other state travels as [`ReadError::Outcome`] or as
/// one of the freshness/availability [`ReadError`] variants that already carry
/// their exact store identity.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadOutcome {
    /// `OBSERVED`: the read resolved over the exact bound identity and the
    /// returned payload observes it.
    Current,
    /// `NOT_RUNNING`: the named source has no activated handler in the current
    /// Store operation catalogue, so no observation of it can be produced at
    /// all. Distinct from `Unavailable`, which means an admitted source could
    /// not be reached.
    NotRunning,
    /// `UNAVAILABLE`: the source is admitted but could not be reached. Carried
    /// by [`StoreReadFailure::Unavailable`] so the exact store identity
    /// survives.
    Unavailable,
    /// `UNKNOWN`: the source answered, but the answer carries no observation of
    /// the bound identity — an empty in-memory payload, or a missing declared
    /// coverage statement. Never an authoritative empty result.
    Unknown,
    /// `STALE`: the answer belongs to a different revision, order or fence
    /// identity than the one this read bound. Carried by
    /// [`ReadError::StaleRevision`] and [`ReadError::ResponseMismatch`].
    Stale,
    /// `CONFLICTED`: the bound closure moved while the read was assembled.
    /// Carried by [`ReadError::RevisionChurn`] and the conflicting store
    /// failures.
    Conflicted,
    /// `PARTIAL`: the source's own declared coverage statement proves the read
    /// covers a bounded subset of the requested source. This is never reported
    /// as a complete current result.
    Partial,
    /// `NOT_APPLICABLE`: no observation of the bound source applies to this
    /// read. Retained as a distinct closed value so an inapplicable read can
    /// never be reported as an observed empty or a current result; the
    /// read coverage dimension carries the same `NOT_APPLICABLE` meaning
    /// concretely in [`ReadCoverage::NotApplicable`].
    NotApplicable,
}

/// Exact caller identity that one retained read is bound to.
///
/// Every component is copied from the caller's validated [`RequestMetadata`],
/// and this type has no constructor that accepts a synthesized product/source
/// pair, so a binding can never name a principal the caller did not present.
/// The product/source pair is the mandatory principal; an attached session or
/// task narrows it and is carried as such. This is an evidence identity, not
/// authority: it records who asked, never what they may do.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadPrincipal {
    product: ProductId,
    source: SourceId,
    session: Option<SessionId>,
    task: Option<TaskId>,
}

impl ReadPrincipal {
    /// Derives the exact caller principal from request metadata.
    ///
    /// The metadata must already be valid: [`ReadService`] validates it before
    /// resolving any binding, so no identity is derived from a rejected
    /// request.
    #[must_use]
    pub fn from_metadata(metadata: &RequestMetadata) -> Self {
        Self {
            product: metadata.product_id.clone(),
            source: metadata.source_id.clone(),
            session: metadata.session_id.clone(),
            task: metadata.task_id.clone(),
        }
    }

    /// Returns the exact product identity the read was requested under.
    #[must_use]
    pub const fn product_id(&self) -> &ProductId {
        &self.product
    }

    /// Returns the exact source identity the read was requested under.
    #[must_use]
    pub const fn source_id(&self) -> &SourceId {
        &self.source
    }

    /// Returns the attached caller session, when the request carries one.
    #[must_use]
    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session.as_ref()
    }

    /// Returns the attached task binding, when the request carries one.
    #[must_use]
    pub const fn task_id(&self) -> Option<&TaskId> {
        self.task.as_ref()
    }
}

/// Exact canonical source one retained read resolved through.
///
/// Both the manifest name and the manifest digest come from the Store operation
/// catalogue, which is the single authority for which named source is
/// activated. A read whose operation has no catalogue entry has no activated
/// source at all and is refused as [`ReadOutcome::NotRunning`] instead of being
/// given a synthesized identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadSourceIdentity {
    /// Closed named operation that owns the projection.
    pub operation: NamedReadOperation,
    /// Exact canonical operation name in the Store catalogue.
    pub operation_name: String,
    /// Exact catalogue manifest name of the activated source.
    pub manifest_name: String,
    /// Exact catalogue manifest digest of the activated source.
    pub manifest_digest: String,
}

/// Exact projection schema identity of the activated Store operation.
///
/// The two digests are independent witnesses of the same schema: the manifest
/// digest covers the whole catalogue entry, and the parameter-schema digest
/// covers the owner-approved typed selector schema the request was admitted
/// against. Neither is derived from the payload, so a payload can never
/// restate — or widen — the schema it was read under.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadSchemaIdentity {
    /// Exact catalogue manifest name of the activated operation.
    pub manifest_name: String,
    /// Exact manifest version of the activated operation.
    pub manifest_version: ContractVersion,
    /// Exact manifest schema digest bound by the catalogue entry.
    pub manifest_schema_digest: String,
    /// Exact digest of the owner-approved typed read-parameter schema.
    pub parameter_schema_digest: String,
}

/// Closed coverage dimension of one named read.
///
/// The values are derived from the Store's own declared read-parameter table
/// plus the caller's declared selectors, and each states exactly what the
/// binding can claim. No percentage, fraction or completeness estimate is
/// derived: a read either binds a declared bound exactly, records that the
/// Store's own bound stays in force, records that it covers one page of a
/// cursor-paged source, or records that no coverage dimension applies.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadCoverage {
    /// `NOT_APPLICABLE`: the Store declares no coverage dimension for this
    /// operation, so no coverage identity applies to this read.
    NotApplicable,
    /// The Store declares a result-set bound for this operation and the caller
    /// declared the exact bound this read is bound to.
    BoundedByDeclaredSelector {
        /// Exact declared result-set bound selector.
        selector: DeclaredResultSelector,
        /// Exact declared bound the caller bound this read to.
        declared_bound: u32,
    },
    /// The Store declares a result-set bound for this operation and the caller
    /// declared no value for it: the Store's own bound stays in force and this
    /// read carries no caller-declared coverage identity. The source's own
    /// response remains the only place a bound and any truncation under it are
    /// observable.
    BoundByStore {
        /// Exact declared result-set bound selector.
        selector: DeclaredResultSelector,
    },
    /// The Store declares an opaque continuation cursor for this operation:
    /// this read covers one page, and the whole source is proven only by
    /// walking cursors to the end. Such a read is never whole-source coverage
    /// on its own.
    PagedByDeclaredCursor {
        /// Exact declared page bound selector, when the operation declares one
        /// in addition to the cursor.
        selector: Option<DeclaredPageSelector>,
    },
}

/// Closed result-set bound selectors the Store declares for named reads.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredResultSelector {
    /// The store-declared `max_records` result-set bound.
    MaxRecords,
}

/// Closed page bound selectors the Store declares for cursor-paged reads.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredPageSelector {
    /// The store-declared `page_limit` page bound.
    PageLimit,
}

/// Exact caller-declared order-head dependency set for one read.
///
/// The Store named-read response exposes revision heads only, so this set is a
/// caller declaration rather than an observed closure, and this is stated
/// rather than hidden. It is nevertheless required on every request — an
/// omitted dependency is a compile error, never a default — and it is verified
/// as far as the current Store contract allows: every declared head must be a
/// valid, unique, non-zero ordering head carrying the request's exact
/// [`StateFence`]. A head bound to any other fence is refused instead of being
/// carried as a live dependency.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOrderingBinding {
    heads: Vec<OrderingHead>,
}

impl ReadOrderingBinding {
    /// Declares that this read depends on no conflict-serialization head.
    ///
    /// This is an explicit declaration, not an omission. Such a read still
    /// proves its coherence through the revision-head closure and the fence,
    /// and the resolved binding records that no order-head dependency applies.
    #[must_use]
    pub const fn without_order_dependency() -> Self {
        Self { heads: Vec::new() }
    }

    /// Declares the exact order-head dependency set this read binds to.
    pub fn of(heads: Vec<OrderingHead>) -> Result<Self, ReadError> {
        let binding = Self { heads };
        binding.validate_against_fence_order()?;
        Ok(binding)
    }

    /// Returns the declared order heads.
    #[must_use]
    pub fn heads(&self) -> &[OrderingHead] {
        &self.heads
    }

    /// Verifies every declared head is a valid, unique ordering head.
    fn validate_against_fence_order(&self) -> Result<(), ReadError> {
        let mut seen = BTreeSet::new();
        for head in &self.heads {
            head.validate().map_err(|error| ReadError::InvalidField {
                field: "ordering_heads".to_owned(),
                reason: error.to_string(),
            })?;
            if !seen.insert(head.scope.clone()) {
                return Err(ReadError::DuplicateField("ordering_heads".to_owned()));
            }
        }
        Ok(())
    }

    /// Verifies every declared head against the request's exact fence.
    ///
    /// A declared dependency is live only at the fence it was declared for. A
    /// head bound to another fence is a mismatched dependency, not a live one,
    /// and is refused here rather than carried into the resolved binding.
    pub fn validate_against(&self, fence: &StateFence) -> Result<(), ReadError> {
        self.validate_against_fence_order()?;
        if self.heads.iter().any(|head| head.state_fence != *fence) {
            return Err(ReadError::OrderingIdentityMismatch {
                declared: self.heads.len(),
            });
        }
        Ok(())
    }
}

/// Exact conditions that void one retained read (I5.20 invalidation conditions).
///
/// The set is the read's own dependency closure: its fence, scope, observed
/// revision heads, declared order heads, resolved source and projection schema.
/// It contains no time-to-live, no eviction rule and no guessed threshold, so
/// revalidating a retained read is an exact comparison of these values and
/// never a judgement call.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadInvalidationSet {
    state_fence: StateFence,
    scope_id: Option<ScopeId>,
    revision_heads: Vec<RevisionHead>,
    ordering_heads: Vec<OrderingHead>,
    source: ReadSourceIdentity,
    schema: ReadSchemaIdentity,
}

impl ReadInvalidationSet {
    /// Returns the exact fence the read was served under.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the exact scope the read was bound to, if any.
    #[must_use]
    pub fn scope_id(&self) -> Option<&ScopeId> {
        self.scope_id.as_ref()
    }

    /// Returns the exact revision heads observed with the read.
    #[must_use]
    pub fn revision_heads(&self) -> &[RevisionHead] {
        &self.revision_heads
    }

    /// Returns the exact order heads the read declared a dependency on.
    #[must_use]
    pub fn ordering_heads(&self) -> &[OrderingHead] {
        &self.ordering_heads
    }

    /// Returns the exact source the read resolved through.
    #[must_use]
    pub const fn source(&self) -> &ReadSourceIdentity {
        &self.source
    }

    /// Returns the exact projection schema the read was admitted against.
    #[must_use]
    pub const fn schema(&self) -> &ReadSchemaIdentity {
        &self.schema
    }
}

/// Exact identity closure one retained read is bound to.
///
/// The closure is the whole of what a consumer needs to revalidate a retained
/// read without consulting this owner again: who asked, for what scope, under
/// which fence, with which consistency mode, over which declared dependencies,
/// which observed revision heads, which declared order heads, which source and
/// projection schema, which coverage identity, and which invalidation
/// conditions. Every component is either copied from a validated caller
/// declaration or resolved from the Store catalogue and the observed heads;
/// none is time-derived, defaulted, or estimated.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadIdentity {
    principal: ReadPrincipal,
    request_id: RequestId,
    operation: NamedReadOperation,
    scope_id: Option<ScopeId>,
    state_fence: StateFence,
    consistency: ReadConsistency,
    declared_dependency_revisions: BTreeMap<RevisionKey, u64>,
    observed_revision_heads: Vec<RevisionHead>,
    ordering: ReadOrderingBinding,
    source: ReadSourceIdentity,
    schema: ReadSchemaIdentity,
    coverage: ReadCoverage,
    invalidation: ReadInvalidationSet,
}

impl ReadIdentity {
    /// Returns the exact caller principal this read is bound to.
    #[must_use]
    pub const fn principal(&self) -> &ReadPrincipal {
        &self.principal
    }

    /// Returns the exact request identity this read was executed under.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the closed named operation that produced the payload.
    #[must_use]
    pub const fn operation(&self) -> NamedReadOperation {
        self.operation
    }

    /// Returns the exact scope this read was bound to, if any.
    #[must_use]
    pub fn scope_id(&self) -> Option<&ScopeId> {
        self.scope_id.as_ref()
    }

    /// Returns the exact fence this read was served under.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the exact consistency mode this read was requested with.
    #[must_use]
    pub const fn consistency(&self) -> ReadConsistency {
        self.consistency
    }

    /// Returns the exact dependency revisions the caller declared.
    #[must_use]
    pub const fn declared_dependency_revisions(&self) -> &BTreeMap<RevisionKey, u64> {
        &self.declared_dependency_revisions
    }

    /// Returns the exact revision heads observed with this read.
    #[must_use]
    pub fn observed_revision_heads(&self) -> &[RevisionHead] {
        &self.observed_revision_heads
    }

    /// Returns the exact order-head dependency this read declared.
    #[must_use]
    pub const fn ordering(&self) -> &ReadOrderingBinding {
        &self.ordering
    }

    /// Returns the exact canonical source this read resolved through.
    #[must_use]
    pub const fn source(&self) -> &ReadSourceIdentity {
        &self.source
    }

    /// Returns the exact projection schema this read was admitted against.
    #[must_use]
    pub const fn schema(&self) -> &ReadSchemaIdentity {
        &self.schema
    }

    /// Returns the exact coverage identity of this read.
    #[must_use]
    pub const fn coverage(&self) -> ReadCoverage {
        self.coverage
    }

    /// Returns the exact conditions that void this retained read.
    #[must_use]
    pub const fn invalidation(&self) -> &ReadInvalidationSet {
        &self.invalidation
    }
}

/// One read result together with the exact identity it is bound to.
///
/// The view keeps the owner-produced payload and its echoed operation, fence,
/// heads and consistency; the identity carries everything the view cannot state
/// about itself, so a consumer that retains the pair can revalidate the read
/// exactly and never has to ask this owner what it meant.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundRead<V> {
    /// The owner-produced view for this read.
    pub view: V,
    /// The exact resolved identity closure of this read.
    pub identity: ReadIdentity,
}

/// Request for one bounded current-state named read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRequest {
    /// Closed named operation owned by the canonical read model.
    pub operation: NamedReadOperation,
    /// Optional scope required by the selected operation.
    pub scope_id: Option<ScopeId>,
    /// Required read consistency.
    pub consistency: ReadConsistency,
    /// Dependency revisions used for at-least and stable reads.
    pub dependency_revisions: BTreeMap<RevisionKey, u64>,
    /// Exact order-head dependency this read binds to; required, never
    /// defaulted. Use [`ReadOrderingBinding::without_order_dependency`] to
    /// state explicitly that no order head applies.
    pub ordering: ReadOrderingBinding,
    /// Closed named selectors; never a raw query string.
    pub parameters: NamedParameters,
    /// Exact source/evidence handles for result lineage.
    #[serde(default)]
    pub provenance_handles: Vec<ProvenanceHandle>,
}

impl StateRequest {
    /// Validates state operation, scope and revision dependencies.
    pub fn validate(&self) -> Result<(), ReadError> {
        if !is_state_operation(self.operation) {
            return Err(ReadError::OperationNotAllowed {
                operation: self.operation,
                context: "state".to_owned(),
            });
        }
        validate_dependencies(&self.dependency_revisions)?;
        self.ordering.validate_against_fence_order()?;
        self.parameters.validate()?;
        if requires_scope(self.operation) && self.scope_id.is_none() {
            return Err(ReadError::ScopeRequired);
        }
        ReadProvenance::from_handles(&self.provenance_handles)?;
        Ok(())
    }
}

/// Request for one explicit-intent query.
///
/// There is no free-text query field: the closed named operation plus the
/// closed selectors in [`NamedParameters`] fully determine the read, and the
/// typed [`QueryIntent`] names the allowed read-only use. Human query text
/// stays at the calling agent surface and never crosses this facade, so it
/// can never be mistaken for a store selector. Exact resource expansion uses
/// [`ResourceRequest`], never this type.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryRequest {
    /// Mandatory semantic intent; exact resources use [`ResourceRequest`].
    pub intent: QueryIntent,
    /// Closed named operation selected by the Governor read model.
    pub operation: NamedReadOperation,
    /// Optional scope to which the query is bound.
    pub scope_id: Option<ScopeId>,
    /// Required read consistency.
    pub consistency: ReadConsistency,
    /// Dependency revisions used for consistency validation.
    pub dependency_revisions: BTreeMap<RevisionKey, u64>,
    /// Exact order-head dependency this read binds to; required, never
    /// defaulted. Use [`ReadOrderingBinding::without_order_dependency`] to
    /// state explicitly that no order head applies.
    pub ordering: ReadOrderingBinding,
    /// Closed named selectors; no physical query syntax is accepted.
    pub parameters: NamedParameters,
    /// Exact source/evidence handles for result lineage.
    #[serde(default)]
    pub provenance_handles: Vec<ProvenanceHandle>,
}

impl QueryRequest {
    /// Validates intent, operation semantics and bounded selectors.
    pub fn validate(&self) -> Result<(), ReadError> {
        validate_dependencies(&self.dependency_revisions)?;
        self.ordering.validate_against_fence_order()?;
        self.parameters.validate()?;
        ReadProvenance::from_handles(&self.provenance_handles)?;
        if requires_scope(self.operation) && self.scope_id.is_none() {
            return Err(ReadError::ScopeRequired);
        }
        if !operation_matches_intent(self.operation, self.intent.mode) {
            return Err(ReadError::InvalidIntentOperation {
                operation: self.operation,
                mode: self.intent.mode,
            });
        }
        Ok(())
    }
}

/// Request for an exact resource expansion.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequest {
    /// Immutable resource URI; no broad listing or URI guessing is allowed.
    pub uri: EliotResourceUri,
    /// Named read operation that owns the resource projection.
    pub operation: NamedReadOperation,
    /// Optional scope for the resource.
    pub scope_id: Option<ScopeId>,
    /// Required read consistency.
    pub consistency: ReadConsistency,
    /// Dependency revisions used for consistency validation.
    pub dependency_revisions: BTreeMap<RevisionKey, u64>,
    /// Exact order-head dependency this read binds to; required, never
    /// defaulted. Use [`ReadOrderingBinding::without_order_dependency`] to
    /// state explicitly that no order head applies.
    pub ordering: ReadOrderingBinding,
    /// Additional closed selectors for the named operation.
    pub parameters: NamedParameters,
    /// Exact source/evidence handles for result lineage.
    #[serde(default)]
    pub provenance_handles: Vec<ProvenanceHandle>,
}

impl ResourceRequest {
    /// Validates exact resource ownership and bounded read parameters.
    pub fn validate(&self) -> Result<(), ReadError> {
        validate_dependencies(&self.dependency_revisions)?;
        self.ordering.validate_against_fence_order()?;
        self.parameters.validate()?;
        ReadProvenance::from_handles(&self.provenance_handles)?;
        if requires_scope(self.operation) && self.scope_id.is_none() {
            return Err(ReadError::ScopeRequired);
        }
        Ok(())
    }
}

/// Current-state response with the store payload kept opaque.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentStateView {
    /// Named operation that produced the payload.
    pub operation: NamedReadOperation,
    /// Exact fence used by the store read.
    pub state_fence: StateFence,
    /// Revision dependencies observed with the payload.
    pub revision_heads: Vec<RevisionHead>,
    /// Opaque typed payload owned by the active read model.
    pub payload: Value,
    /// Exact lineage and its allowed read-only disposition.
    pub provenance: ReadProvenance,
    /// Consistency actually requested for this result.
    pub consistency: ReadConsistency,
}

/// Query response with explicit intent and opaque payload.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryResult {
    /// Intent used to interpret the result.
    pub intent: QueryIntent,
    /// Named operation that produced the payload.
    pub operation: NamedReadOperation,
    /// Exact fence used by the store read.
    pub state_fence: StateFence,
    /// Revision dependencies observed with the payload.
    pub revision_heads: Vec<RevisionHead>,
    /// Opaque typed payload owned by the active read model.
    pub payload: Value,
    /// Exact lineage and its allowed read-only disposition.
    pub provenance: ReadProvenance,
    /// Consistency actually requested for this result.
    pub consistency: ReadConsistency,
}

/// Exact resource response; expansion never re-executes an originating tool.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceContent {
    /// Exact resource identity requested by the caller.
    pub uri: EliotResourceUri,
    /// Named operation that owns the resource projection.
    pub operation: NamedReadOperation,
    /// Exact fence used by the store read.
    pub state_fence: StateFence,
    /// Revision dependencies observed with the resource.
    pub revision_heads: Vec<RevisionHead>,
    /// Opaque immutable resource payload.
    pub payload: Value,
    /// Exact lineage and its allowed read-only disposition.
    pub provenance: ReadProvenance,
    /// Consistency actually requested for this resource.
    pub consistency: ReadConsistency,
}

/// Governor read failures. No variant exposes provider secrets or raw SQL.
#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadError {
    /// A required field is malformed or out of bounds.
    #[error("invalid read field {field}: {reason}")]
    InvalidField {
        /// Name of the malformed field.
        field: String,
        /// Validation reason for the malformed field.
        reason: String,
    },
    /// A required textual field is blank.
    #[error("{0} must not be empty")]
    EmptyField(String),
    /// Duplicate exact handles or dependency keys were supplied.
    #[error("duplicate values in {0}")]
    DuplicateField(String),
    /// An operation is not legal for the requested facade context.
    #[error("named operation {operation:?} is not allowed for {context}")]
    OperationNotAllowed {
        /// Closed named operation.
        operation: NamedReadOperation,
        /// Facade context.
        context: String,
    },
    /// Query mode and named operation disagree.
    #[error("named operation {operation:?} does not support query mode {mode:?}")]
    InvalidIntentOperation {
        /// Closed named operation.
        operation: NamedReadOperation,
        /// Explicit query mode.
        mode: QueryMode,
    },
    /// A broad query omitted its required intent.
    #[error("query intent is required for a broad read")]
    MissingIntent,
    /// A scope-bound operation omitted its scope.
    #[error("read operation requires a scope")]
    ScopeRequired,
    /// URI is not an immutable exact resource URI.
    #[error("invalid exact resource URI")]
    InvalidResourceUri,
    /// Dependency revisions are absent for a consistency mode that needs them.
    #[error("read consistency requires dependency revisions")]
    MissingDependencies,
    /// A dependency revision was zero or otherwise invalid.
    #[error("invalid dependency revision")]
    InvalidDependencyRevision,
    /// Store response changed the requested operation or fence.
    #[error("named read response does not match request fence or operation")]
    ResponseMismatch,
    /// Stable read observed a revision change during assembly.
    #[error("read dependency revisions changed during stable read")]
    RevisionChurn,
    /// A read response is older than the declared minimum revision.
    #[error("read response is behind the declared minimum revision")]
    StaleRevision,
    /// A declared order-head dependency is bound to a fence other than the
    /// read's exact request fence.
    ///
    /// Such a head is not a live dependency for this read: it is refused
    /// instead of being carried into the resolved binding, so a retained read
    /// can never claim an order dependency it did not hold.
    #[error("{declared} declared order heads do not carry the read's exact fence")]
    OrderingIdentityMismatch {
        /// Number of declared order heads in the refused binding.
        declared: usize,
    },
    /// The read produced no observation, and its non-current state is one the
    /// Store error set cannot express.
    ///
    /// `NotRunning` (no activated Store source), `Unknown` (an answer that does
    /// not observe the bound identity) and `Partial` (a Store-declared
    /// truncated coverage statement) are owner-level observations rather than
    /// store transport failures, so they travel as the closed
    /// [`ReadOutcome`] value. `Unavailable`, `Stale` and `Conflicted` keep
    /// their existing typed variants, which carry the exact store identity.
    #[error("read produced no current observation: {0:?}")]
    Outcome(ReadOutcome),
    /// Store boundary rejected the named read, with its exact typed identity.
    ///
    /// Every [`StoreError`] discriminant maps to exactly one variant below, so
    /// stale, conflicted, missing, unknown, partial, and unavailable outcomes
    /// stay distinguishable and can never collapse into a successful
    /// empty/current result. The mapping in `From<StoreError>` is exhaustive:
    /// a future store variant fails compilation here until it is assigned an
    /// explicit disposition, never silently erased.
    #[error("store read: {0}")]
    Store(StoreReadFailure),
}

/// Typed store-boundary failure for Governor reads.
///
/// This mirrors every [`StoreError`] discriminant in store-neutral Governor
/// vocabulary. Static store details (`field`/`reason`) become bounded owned
/// strings; transitions digests keep their expected/observed pair; contract
/// inner errors keep their exact display text. No variant carries provider
/// secrets or raw query text.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreReadFailure {
    /// A required field is malformed or out of bounds.
    InvalidField {
        /// Name of the malformed field.
        field: String,
        /// Validation reason for the malformed field.
        reason: String,
    },
    /// A required field is empty.
    Empty {
        /// Name of the empty field.
        field: String,
    },
    /// Duplicate exact values were supplied.
    Duplicate {
        /// Name of the duplicated field.
        field: String,
    },
    /// Foundation contract rejection, with its exact display text.
    Foundation(String),
    /// Security contract rejection, with its exact display text.
    Security(String),
    /// Receipt contract rejection, with its exact display text.
    Receipt(String),
    /// The named operation is unknown to the store catalogue.
    UnknownOperation,
    /// The operation manifest digest does not match.
    ManifestMismatch,
    /// The transition class ceiling was exceeded.
    TransitionClassExceeded,
    /// The effect ceiling was exceeded.
    EffectCeilingExceeded,
    /// The state fence does not match; never served as current.
    FenceMismatch,
    /// A revision conflict was observed.
    RevisionConflict,
    /// An ordering conflict was observed.
    OrderingConflict,
    /// The projection publication is invalid.
    InvalidProjection,
    /// The outbox intent is invalid.
    InvalidOutbox,
    /// The terminal receipt is invalid.
    InvalidReceipt,
    /// An identity conflict was observed.
    IdentityConflict,
    /// A transition digest mismatch with the claimed and observed digests.
    TransitionDigestMismatch {
        /// Claimed digest.
        expected: String,
        /// Recomputed digest.
        observed: String,
    },
    /// The receipt was not found.
    ReceiptNotFound,
    /// The receipt envelope is missing; write outcome is unknown.
    MissingReceiptEnvelope,
    /// The payload exceeds the named-operation limit.
    PayloadTooLarge,
    /// The store is unavailable; never an empty success.
    Unavailable,
    /// Canonical serialization failed, with its exact display text.
    Serialization(String),
}

impl std::fmt::Display for StoreReadFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(formatter, "invalid field {field}: {reason}")
            }
            Self::Empty { field } => write!(formatter, "empty field {field}"),
            Self::Duplicate { field } => write!(formatter, "duplicate values in {field}"),
            Self::Foundation(detail)
            | Self::Security(detail)
            | Self::Receipt(detail)
            | Self::Serialization(detail) => formatter.write_str(detail),
            Self::UnknownOperation => formatter.write_str("unknown named operation"),
            Self::ManifestMismatch => formatter.write_str("operation manifest digest mismatch"),
            Self::TransitionClassExceeded => {
                formatter.write_str("transition class ceiling exceeded")
            }
            Self::EffectCeilingExceeded => formatter.write_str("effect ceiling exceeded"),
            Self::FenceMismatch => formatter.write_str("state fence mismatch"),
            Self::RevisionConflict => formatter.write_str("revision conflict"),
            Self::OrderingConflict => formatter.write_str("ordering conflict"),
            Self::InvalidProjection => formatter.write_str("invalid projection publication"),
            Self::InvalidOutbox => formatter.write_str("invalid outbox intent"),
            Self::InvalidReceipt => formatter.write_str("invalid terminal receipt"),
            Self::IdentityConflict => formatter.write_str("identity conflict"),
            Self::TransitionDigestMismatch { expected, observed } => write!(
                formatter,
                "transition digest mismatch: expected {expected}, observed {observed}"
            ),
            Self::ReceiptNotFound => formatter.write_str("receipt not found"),
            Self::MissingReceiptEnvelope => {
                formatter.write_str("receipt envelope is missing; write outcome is unknown")
            }
            Self::PayloadTooLarge => formatter.write_str("payload exceeds named-operation limit"),
            Self::Unavailable => formatter.write_str("store unavailable"),
        }
    }
}

impl From<StoreError> for StoreReadFailure {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::InvalidField { field, reason } => Self::InvalidField {
                field: field.to_owned(),
                reason: reason.to_owned(),
            },
            StoreError::Empty { field } => Self::Empty {
                field: field.to_owned(),
            },
            StoreError::Duplicate { field } => Self::Duplicate {
                field: field.to_owned(),
            },
            StoreError::Foundation(error) => Self::Foundation(error.to_string()),
            StoreError::Security(error) => Self::Security(error.to_string()),
            StoreError::Receipt(error) => Self::Receipt(error.to_string()),
            StoreError::UnknownOperation => Self::UnknownOperation,
            StoreError::ManifestMismatch => Self::ManifestMismatch,
            StoreError::TransitionClassExceeded => Self::TransitionClassExceeded,
            StoreError::EffectCeilingExceeded => Self::EffectCeilingExceeded,
            StoreError::FenceMismatch => Self::FenceMismatch,
            StoreError::RevisionConflict => Self::RevisionConflict,
            StoreError::OrderingConflict => Self::OrderingConflict,
            StoreError::InvalidProjection => Self::InvalidProjection,
            StoreError::InvalidOutbox => Self::InvalidOutbox,
            StoreError::InvalidReceipt => Self::InvalidReceipt,
            StoreError::IdentityConflict => Self::IdentityConflict,
            StoreError::TransitionDigestMismatch { expected, observed } => {
                Self::TransitionDigestMismatch { expected, observed }
            }
            StoreError::ReceiptNotFound => Self::ReceiptNotFound,
            StoreError::MissingReceiptEnvelope => Self::MissingReceiptEnvelope,
            StoreError::PayloadTooLarge => Self::PayloadTooLarge,
            StoreError::Unavailable => Self::Unavailable,
            StoreError::Serialization(detail) => Self::Serialization(detail),
        }
    }
}

impl From<StoreError> for ReadError {
    fn from(error: StoreError) -> Self {
        Self::Store(StoreReadFailure::from(error))
    }
}

/// Read API implemented by the Governor service boundary.
///
/// `state`, `query` and `resource` return the owner view; `bound_state`,
/// `bound_query` and `bound_resource` return the same view together with the
/// exact resolved [`ReadIdentity`]. Both families are the single
/// implementation in [`ReadService`]: the plain calls delegate to the bound
/// ones and drop only the identity, so there is one consistency algorithm, one
/// source resolution and one outcome classification in this package.
#[allow(async_fn_in_trait)]
pub trait ReadApi {
    /// Returns one bounded current-state view.
    async fn state(
        &self,
        ctx: &RequestMetadata,
        request: StateRequest,
    ) -> Result<CurrentStateView, ReadError>;
    /// Executes one explicit-intent named query.
    async fn query(
        &self,
        ctx: &RequestMetadata,
        request: QueryRequest,
    ) -> Result<QueryResult, ReadError>;
    /// Expands one exact immutable resource URI.
    async fn resource(
        &self,
        ctx: &RequestMetadata,
        request: ResourceRequest,
    ) -> Result<ResourceContent, ReadError>;
    /// Returns one bounded current-state view bound to its exact identity.
    async fn bound_state(
        &self,
        ctx: &RequestMetadata,
        request: StateRequest,
    ) -> Result<BoundRead<CurrentStateView>, ReadError>;
    /// Executes one explicit-intent named query bound to its exact identity.
    async fn bound_query(
        &self,
        ctx: &RequestMetadata,
        request: QueryRequest,
    ) -> Result<BoundRead<QueryResult>, ReadError>;
    /// Expands one exact immutable resource URI bound to its exact identity.
    async fn bound_resource(
        &self,
        ctx: &RequestMetadata,
        request: ResourceRequest,
    ) -> Result<BoundRead<ResourceContent>, ReadError>;
}

/// Local Governor read port for daemon-side query/packet serving.
///
/// This is the MGR02-owned port for `eliot.query` / `eliot.packet` answers
/// (HANDOFF-LRR-GOV, #18). It must not be confused with `KernelGovernorPort`
/// in `eliot-mcp` (MGR01-owned): this trait lives in `eliot-read` and is
/// blanket-implemented over `ReadService<C: CanonicalReadClient>` so no
/// second consistency algorithm is created.
#[allow(async_fn_in_trait)]
pub trait LocalReadPort {
    /// Answers one bounded evidence query live.
    ///
    /// Builds a `Verification`-intent `GetEvidencePack` request (`Eventual`,
    /// no dependencies, `subject` + decimal `max_records` selectors) and
    /// delegates to [`ReadApi::query`]. The exact record/provenance returns
    /// on success; a wrong fence or an over-bound request is refused
    /// fail-closed by the facade/store gates.
    async fn evidence_query(
        &self,
        ctx: &RequestMetadata,
        scope: ScopeId,
        subject: String,
        max_records: u32,
    ) -> Result<QueryResult, ReadError>;
    /// Answers one projection-inputs read (port-shape only until storage
    /// activates the operation).
    ///
    /// Validates `packet_ref` / `material_refs` and the facade request shape
    /// (`ContextReconstruction` intent + `GetUnderstandingProjectionInputs`),
    /// then fails closed with a typed `Unavailable` store error until MGR04
    /// (#19) activates the catalogue row, parameter schema, and adapter
    /// handlers. Never a stub, never canned data, never `Ok`-empty
    /// masquerading as success.
    async fn projection_inputs(
        &self,
        ctx: &RequestMetadata,
        scope: ScopeId,
        packet_ref: Option<String>,
        material_refs: Vec<String>,
    ) -> Result<QueryResult, ReadError>;
}

impl<C: CanonicalReadClient> LocalReadPort for ReadService<C> {
    async fn evidence_query(
        &self,
        ctx: &RequestMetadata,
        scope: ScopeId,
        subject: String,
        max_records: u32,
    ) -> Result<QueryResult, ReadError> {
        text(&subject, "subject")?;
        if max_records == 0 {
            return Err(ReadError::InvalidField {
                field: "max_records".to_owned(),
                reason: "must be a positive decimal bound".to_owned(),
            });
        }
        let intent = QueryIntent {
            mode: QueryMode::Verification,
            time_scope: TimeScope::EvidenceWindow,
            branch_environment_scope: BranchEnvironmentScope::LocalEnvironment,
            freshness_policy: FreshnessPolicy::ExactCapturedRecords,
            required_assurance: RequiredAssurance::VerifierEvidence,
        };
        let parameters = NamedParameters::from_map(BTreeMap::from([
            ("subject".to_owned(), Value::String(subject)),
            (
                "max_records".to_owned(),
                Value::String(max_records.to_string()),
            ),
        ]))?;
        let request = QueryRequest {
            intent,
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(scope),
            consistency: ReadConsistency::Eventual,
            dependency_revisions: BTreeMap::new(),
            // This port declares no conflict-serialization head dependency: its
            // coherence is proven by the scope-bound evidence projection under
            // the request fence alone. The declaration is explicit so the
            // resolved identity records it rather than leaving it unstated.
            ordering: ReadOrderingBinding::without_order_dependency(),
            parameters,
            provenance_handles: Vec::new(),
        };
        ReadApi::query(self, ctx, request).await
    }

    async fn projection_inputs(
        &self,
        ctx: &RequestMetadata,
        scope: ScopeId,
        packet_ref: Option<String>,
        material_refs: Vec<String>,
    ) -> Result<QueryResult, ReadError> {
        ctx.validate().map_err(|error| ReadError::InvalidField {
            field: "request_metadata".to_owned(),
            reason: error.to_string(),
        })?;
        if let Some(ref packet) = packet_ref {
            text(packet, "packet.packet_ref")?;
        }
        {
            let mut seen = BTreeSet::new();
            for material in &material_refs {
                text(material, "packet.material_refs")?;
                if !seen.insert(material.clone()) {
                    return Err(ReadError::DuplicateField("packet.material_refs".to_owned()));
                }
            }
        }
        let intent = QueryIntent {
            mode: QueryMode::ContextReconstruction,
            time_scope: TimeScope::ProjectionWindow,
            branch_environment_scope: BranchEnvironmentScope::LocalEnvironment,
            freshness_policy: FreshnessPolicy::ProjectionInputsOnly,
            required_assurance: RequiredAssurance::ReconstructionInputs,
        };
        // Facade-valid shape today (scope-bound, admitted intent/operation).
        // `packet_ref` / `material_refs` are validated above but map to no
        // selector yet: no `packet_ref` / `material_refs` parameter mapping
        // exists until MGR04 (#19) declares the storage schema, so no
        // selectors cross and no free text enters the request.
        let request = QueryRequest {
            intent,
            operation: NamedReadOperation::GetUnderstandingProjectionInputs,
            scope_id: Some(scope),
            consistency: ReadConsistency::Eventual,
            dependency_revisions: BTreeMap::new(),
            // Explicit no-order-dependency declaration, for the same reason as
            // `evidence_query`: the resolved identity states it rather than
            // leaving the order-head dimension unstated.
            ordering: ReadOrderingBinding::without_order_dependency(),
            parameters: NamedParameters::new(),
            provenance_handles: Vec::new(),
        };
        request.validate()?;
        // Storage has no catalogue row, parameter schema, or adapter handler
        // for this operation on base: fail closed, never `Ok`-empty.
        Err(ReadError::Store(StoreReadFailure::Unavailable))
    }
}

/// Governor read service over a store-neutral canonical client.
pub struct ReadService<C> {
    store: C,
}

impl<C: CanonicalReadClient> ReadService<C> {
    /// Creates a read service over the caller-owned store client.
    pub const fn new(store: C) -> Self {
        Self { store }
    }

    /// Returns the underlying store client to the owning composition root.
    pub fn into_store(self) -> C {
        self.store
    }

    /// The single read engine of this package: resolve the identity closure,
    /// enforce the declared dependencies, dispatch the one closed named read,
    /// classify the outcome, and refuse anything that is not current.
    ///
    /// This is the only place that talks to [`CanonicalReadClient`], so there
    /// is no second consistency algorithm, no second source resolution, and no
    /// second outcome vocabulary anywhere in this owner.
    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        ctx: &RequestMetadata,
        operation: NamedReadOperation,
        scope_id: Option<ScopeId>,
        consistency: ReadConsistency,
        dependencies: &BTreeMap<RevisionKey, u64>,
        ordering: &ReadOrderingBinding,
        parameters: &NamedParameters,
        handles: &[ProvenanceHandle],
    ) -> Result<BoundRead<NamedReadResponse>, ReadError> {
        ctx.validate().map_err(|error| ReadError::InvalidField {
            field: "request_metadata".to_owned(),
            reason: error.to_string(),
        })?;
        let (source, schema) = resolve_source_and_schema(operation)?;
        let coverage = resolve_coverage(operation, parameters)?;
        ordering.validate_against(&ctx.state_fence)?;
        if matches!(
            consistency,
            ReadConsistency::StableScope | ReadConsistency::ExactFence
        ) && dependencies.is_empty()
        {
            return Err(ReadError::MissingDependencies);
        }
        let keys: Vec<RevisionKey> = dependencies.keys().cloned().collect();
        let before = if keys.is_empty() {
            Vec::new()
        } else {
            self.store.revision_heads(keys.clone()).await?
        };
        validate_minimum_revisions(&before, dependencies)?;
        let request = NamedReadRequest {
            operation,
            scope_id: scope_id.clone(),
            consistency,
            state_fence: ctx.state_fence.clone(),
            parameters: parameters.as_map().clone(),
        };
        request.validate()?;
        let response = self.store.execute_named(request).await?;
        response.validate()?;
        if response.operation != operation || response.state_fence != ctx.state_fence {
            return Err(ReadError::ResponseMismatch);
        }
        validate_response_heads(&response, &ctx.state_fence)?;
        validate_minimum_revisions(&response.revision_heads, dependencies)?;
        if matches!(
            consistency,
            ReadConsistency::StableScope | ReadConsistency::ExactFence
        ) {
            let after = self.store.revision_heads(keys).await?;
            validate_minimum_revisions(&after, dependencies)?;
            if !same_dependency_heads(&before, &after, dependencies) {
                return Err(ReadError::RevisionChurn);
            }
            if !same_dependency_heads(&before, &response.revision_heads, dependencies) {
                return Err(ReadError::RevisionChurn);
            }
        }
        if consistency == ReadConsistency::ExactFence
            && response
                .revision_heads
                .iter()
                .filter(|head| dependencies.contains_key(&head.key))
                .any(|head| dependencies.get(&head.key) != Some(&head.revision))
        {
            return Err(ReadError::StaleRevision);
        }
        classify_payload_coverage(operation, &response.payload)?;
        let _ = ReadProvenance::from_handles(handles)?;
        let identity = ReadIdentity {
            principal: ReadPrincipal::from_metadata(ctx),
            request_id: ctx.request_id.clone(),
            operation,
            scope_id: scope_id.clone(),
            state_fence: ctx.state_fence.clone(),
            consistency,
            declared_dependency_revisions: dependencies.clone(),
            observed_revision_heads: response.revision_heads.clone(),
            ordering: ordering.clone(),
            source: source.clone(),
            schema: schema.clone(),
            coverage,
            invalidation: ReadInvalidationSet {
                state_fence: ctx.state_fence.clone(),
                scope_id: scope_id.clone(),
                revision_heads: response.revision_heads.clone(),
                ordering_heads: ordering.heads().to_vec(),
                source: source.clone(),
                schema: schema.clone(),
            },
        };
        Ok(BoundRead {
            view: response,
            identity,
        })
    }
}

impl<C: CanonicalReadClient> ReadApi for ReadService<C> {
    async fn state(
        &self,
        ctx: &RequestMetadata,
        request: StateRequest,
    ) -> Result<CurrentStateView, ReadError> {
        Ok(self.bound_state(ctx, request).await?.view)
    }

    async fn query(
        &self,
        ctx: &RequestMetadata,
        request: QueryRequest,
    ) -> Result<QueryResult, ReadError> {
        Ok(self.bound_query(ctx, request).await?.view)
    }

    async fn resource(
        &self,
        ctx: &RequestMetadata,
        request: ResourceRequest,
    ) -> Result<ResourceContent, ReadError> {
        Ok(self.bound_resource(ctx, request).await?.view)
    }

    async fn bound_state(
        &self,
        ctx: &RequestMetadata,
        request: StateRequest,
    ) -> Result<BoundRead<CurrentStateView>, ReadError> {
        request.validate()?;
        let bound = self
            .execute(
                ctx,
                request.operation,
                request.scope_id,
                request.consistency,
                &request.dependency_revisions,
                &request.ordering,
                &request.parameters,
                &request.provenance_handles,
            )
            .await?;
        let view = CurrentStateView {
            operation: bound.view.operation,
            state_fence: bound.view.state_fence,
            revision_heads: bound.view.revision_heads,
            payload: bound.view.payload,
            provenance: ReadProvenance::from_handles(&request.provenance_handles)?,
            consistency: request.consistency,
        };
        Ok(BoundRead {
            view,
            identity: bound.identity,
        })
    }

    async fn bound_query(
        &self,
        ctx: &RequestMetadata,
        request: QueryRequest,
    ) -> Result<BoundRead<QueryResult>, ReadError> {
        request.validate()?;
        let bound = self
            .execute(
                ctx,
                request.operation,
                request.scope_id,
                request.consistency,
                &request.dependency_revisions,
                &request.ordering,
                &request.parameters,
                &request.provenance_handles,
            )
            .await?;
        let view = QueryResult {
            intent: request.intent,
            operation: bound.view.operation,
            state_fence: bound.view.state_fence,
            revision_heads: bound.view.revision_heads,
            payload: bound.view.payload,
            provenance: ReadProvenance::from_handles(&request.provenance_handles)?,
            consistency: request.consistency,
        };
        Ok(BoundRead {
            view,
            identity: bound.identity,
        })
    }

    async fn bound_resource(
        &self,
        ctx: &RequestMetadata,
        request: ResourceRequest,
    ) -> Result<BoundRead<ResourceContent>, ReadError> {
        request.validate()?;
        let mut parameters = request.parameters.clone();
        parameters.insert_exact("resource_uri", request.uri.as_str())?;
        let bound = self
            .execute(
                ctx,
                request.operation,
                request.scope_id.clone(),
                request.consistency,
                &request.dependency_revisions,
                &request.ordering,
                &parameters,
                &request.provenance_handles,
            )
            .await?;
        let view = ResourceContent {
            uri: request.uri,
            operation: bound.view.operation,
            state_fence: bound.view.state_fence,
            revision_heads: bound.view.revision_heads,
            payload: bound.view.payload,
            provenance: ReadProvenance::from_handles(&request.provenance_handles)?,
            consistency: request.consistency,
        };
        Ok(BoundRead {
            view,
            identity: bound.identity,
        })
    }
}

/// Resolves the exact activated Store source and projection schema of one
/// named read.
///
/// The Store operation catalogue is the single authority for which source is
/// activated, and it is read here without re-declaring anything. An operation
/// with no activated entry has no running source, so it is refused as
/// [`ReadOutcome::NotRunning`] instead of being dispatched and answered by an
/// unknown-operation error that a consumer could mistake for a refusal of the
/// caller rather than of the source.
///
/// Both schema witnesses come from the Store: the catalogue entry's own schema
/// digest and the digest over the owner-approved typed read-parameter schema the
/// request is admitted against. Neither is read from the payload, so a payload
/// can never restate or widen the schema it was read under.
fn resolve_source_and_schema(
    operation: NamedReadOperation,
) -> Result<(ReadSourceIdentity, ReadSchemaIdentity), ReadError> {
    let operation_name = named_read_operation_name(operation);
    if !activated_read_operations().contains(&operation) {
        return Err(ReadError::Outcome(ReadOutcome::NotRunning));
    }
    let entries = generated_manifests()?;
    let entry = entries
        .iter()
        .find(|entry| entry.name == operation_name)
        .ok_or(ReadError::Outcome(ReadOutcome::NotRunning))?;
    let source = ReadSourceIdentity {
        operation,
        operation_name: operation_name.to_owned(),
        manifest_name: entry.name.clone(),
        manifest_digest: entry.digest.as_str().to_owned(),
    };
    let schema = ReadSchemaIdentity {
        manifest_name: entry.name.clone(),
        manifest_version: entry.version,
        manifest_schema_digest: entry.schema_digest.clone(),
        parameter_schema_digest: parameter_schema_digest(&project_parameter_schema(operation))?,
    };
    Ok((source, schema))
}

/// Returns the generated Store operation catalogue.
///
/// The catalogue is a pure function of the Store's own declaration table, so
/// resolving it here introduces no second source of truth; a catalogue that
/// cannot be generated is a store contract failure, not an empty read.
fn generated_manifests() -> Result<Vec<eliot_store_api::NamedOperationManifest>, ReadError> {
    eliot_store_api::generated_operation_manifests()
        .map_err(StoreReadFailure::from)
        .map_err(ReadError::Store)
}

/// Resolves the exact coverage identity of one named read from the Store's own
/// declared read-parameter table plus the caller's declared selectors.
///
/// A result-set bound, a cursor continuation, or the absence of any coverage
/// dimension is read from the declaration table rather than assumed, and the
/// caller's declared bound is echoed exactly. No percentage or completeness
/// estimate is derived here: coverage is a statement about which bound was in
/// force, never about how much of the source a read happened to see.
fn resolve_coverage(
    operation: NamedReadOperation,
    parameters: &NamedParameters,
) -> Result<ReadCoverage, ReadError> {
    let declarations = declared_read_parameters(operation);
    let mut result_bound = None;
    let mut page_bound = None;
    let mut cursor = false;
    for declaration in declarations {
        match declaration.name {
            "max_records" => result_bound = Some(DeclaredResultSelector::MaxRecords),
            "page_limit" => page_bound = Some(DeclaredPageSelector::PageLimit),
            "cursor" => cursor = true,
            _ => {}
        }
    }
    if let Some(selector) = result_bound {
        return Ok(
            match declared_bound(parameters, declaration_name(selector))? {
                Some(declared_bound) => ReadCoverage::BoundedByDeclaredSelector {
                    selector,
                    declared_bound,
                },
                None => ReadCoverage::BoundByStore { selector },
            },
        );
    }
    if cursor {
        return Ok(ReadCoverage::PagedByDeclaredCursor {
            selector: page_bound,
        });
    }
    Ok(ReadCoverage::NotApplicable)
}

/// Returns the exact Store selector name for one declared coverage selector.
const fn declaration_name(selector: DeclaredResultSelector) -> &'static str {
    match selector {
        DeclaredResultSelector::MaxRecords => "max_records",
    }
}

/// Reads one caller-declared positive decimal bound out of the closed selectors.
fn declared_bound(parameters: &NamedParameters, selector: &str) -> Result<Option<u32>, ReadError> {
    let Some(raw) = parameters.as_map().get(selector) else {
        return Ok(None);
    };
    let text = raw.as_str().ok_or_else(|| ReadError::InvalidField {
        field: format!("coverage.{selector}"),
        reason: "declared bound must be a decimal string".to_owned(),
    })?;
    let bound: u32 = text.parse().map_err(|_| ReadError::InvalidField {
        field: format!("coverage.{selector}"),
        reason: "declared bound must be a positive decimal".to_owned(),
    })?;
    if bound == 0 {
        return Err(ReadError::InvalidField {
            field: format!("coverage.{selector}"),
            reason: "declared bound must be a positive decimal".to_owned(),
        });
    }
    Ok(Some(bound))
}

/// Refuses a successful response that does not observe its own bound identity.
///
/// Two cases are refused, and neither may become a successful empty or current
/// result:
///
/// * a payload that is a bare JSON `null` is an unobserved in-memory value, not
///   an authoritative statement that the projection is empty — it is `Unknown`;
/// * for the operations whose Store contract types a page coverage statement
///   ([`ExperienceRangePage`]), the statement must decode and must describe the
///   records it carries — an undecodable or undescribed statement is `Unknown`,
///   and a statement that proves further rows exist past the declared bound is
///   `Partial`.
///
/// Every other operation keeps its payload opaque here: its own consumer owns
/// the payload contract, and this owner states only that the read is bound to
/// the exact [`ReadCoverage`] identity it resolved above.
fn classify_payload_coverage(
    operation: NamedReadOperation,
    payload: &Value,
) -> Result<(), ReadError> {
    if payload.is_null() {
        return Err(ReadError::Outcome(ReadOutcome::Unknown));
    }
    if !declares_store_coverage_statement(operation) {
        return Ok(());
    }
    let page: ExperienceRangePage = serde_json::from_value(payload.clone())
        .map_err(|_| ReadError::Outcome(ReadOutcome::Unknown))?;
    if page.matched_total != page.records.len() {
        return Err(ReadError::Outcome(ReadOutcome::Unknown));
    }
    if page.truncated {
        return Err(ReadError::Outcome(ReadOutcome::Partial));
    }
    Ok(())
}

/// Returns whether the Store contract types a page coverage statement for this
/// operation.
///
/// The answer is read from the Store's own exported contract: only the two
/// experience range reads publish a typed [`ExperienceRangePage`] statement, so
/// only they are gated on it. Any operation that starts publishing such a
/// statement gains the gate through its Store contract, not through a decision
/// made here.
const fn declares_store_coverage_statement(operation: NamedReadOperation) -> bool {
    matches!(
        operation,
        NamedReadOperation::GetExperienceBankRange | NamedReadOperation::GetAgentFeedbackRange
    )
}

/// Returns the stable contract identity for protocol/schema handshakes.
pub fn contract_identity() -> Result<ContractIdentity, eliot_contracts::ContractError> {
    #[derive(Serialize)]
    struct Shape {
        surface: &'static str,
        version: ContractVersion,
        raw_query_rule: &'static str,
        stable_read_rule: &'static str,
        provenance_rule: &'static str,
        identity_rule: &'static str,
        ordering_rule: &'static str,
        outcome_rule: &'static str,
    }

    make_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &Shape {
            surface: "governor_named_read_query_and_resource_facade",
            version: CONTRACT_VERSION,
            raw_query_rule: "closed_named_operations_and_scalar_selectors_only",
            stable_read_rule: "revision_heads_before_and_after_named_read",
            provenance_rule: "exact_handles_or_read_only_unavailable_disposition",
            identity_rule: "principal_scope_fence_heads_consistency_source_schema_coverage_and_invalidation",
            ordering_rule: "declared_order_heads_must_carry_the_exact_read_fence",
            outcome_rule: "only_current_is_successful_not_running_unknown_partial_stay_distinct",
        },
    )
}

fn is_state_operation(operation: NamedReadOperation) -> bool {
    matches!(
        operation,
        NamedReadOperation::GetRevisionHeads
            | NamedReadOperation::GetScopeRevisionView
            | NamedReadOperation::GetTaskState
            | NamedReadOperation::GetCurrentEpistemicPosition
            | NamedReadOperation::GetAttentionAndProblems
            | NamedReadOperation::GetModuleCatalogState
            | NamedReadOperation::GetCapabilityEvidenceState
            | NamedReadOperation::GetConformanceState
            | NamedReadOperation::GetMailbox
    )
}

fn requires_scope(operation: NamedReadOperation) -> bool {
    matches!(
        operation,
        NamedReadOperation::GetScopeRevisionView
            | NamedReadOperation::GetTaskState
            | NamedReadOperation::GetCurrentEpistemicPosition
            | NamedReadOperation::GetEvidencePack
            | NamedReadOperation::GetUnderstandingProjectionInputs
            | NamedReadOperation::GetAttentionAndProblems
            | NamedReadOperation::GetCapabilityEvidenceState
            | NamedReadOperation::GetConformanceState
            | NamedReadOperation::GetMailbox
            | NamedReadOperation::GetAuditRange
            | NamedReadOperation::GetExperienceBankRange
            | NamedReadOperation::GetAgentFeedbackRange
    )
}

fn operation_matches_intent(operation: NamedReadOperation, mode: QueryMode) -> bool {
    match mode {
        QueryMode::CurrentPosition => matches!(
            operation,
            NamedReadOperation::GetCurrentEpistemicPosition
                | NamedReadOperation::GetScopeRevisionView
                | NamedReadOperation::GetRevisionHeads
        ),
        QueryMode::HistoricalReconstruction => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetAuditRange
                | NamedReadOperation::GetTaskState
                | NamedReadOperation::GetExperienceBankRange
                | NamedReadOperation::GetAgentFeedbackRange
        ),
        QueryMode::Provenance => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetAuditRange
                | NamedReadOperation::ResolveWriteReceipt
                | NamedReadOperation::GetExperienceBankRange
                | NamedReadOperation::GetAgentFeedbackRange
        ),
        QueryMode::Navigation => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetScopeRevisionView
                | NamedReadOperation::GetRevisionHeads
        ),
        QueryMode::Verification => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetUnderstandingProjectionInputs
                | NamedReadOperation::GetConformanceState
        ),
        QueryMode::ChangeImpact => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetUnderstandingProjectionInputs
        ),
        QueryMode::ContextReconstruction => matches!(
            operation,
            NamedReadOperation::GetEvidencePack
                | NamedReadOperation::GetUnderstandingProjectionInputs
                | NamedReadOperation::GetCurrentEpistemicPosition
                | NamedReadOperation::GetTaskState
                | NamedReadOperation::GetAttentionAndProblems
                | NamedReadOperation::GetCapabilityEvidenceState
        ),
    }
}

/// Closed named-read operations admitted to [`QueryMode::ContextReconstruction`].
///
/// Canonical role order follows the T11 acquisition table: task frame,
/// critical attention, current epistemic position, understanding-projection
/// inputs (serving both the cue-activation and negative-memory roles through
/// distinct closed selectors), evidence pack, and capability evidence
/// (affordances). Every entry satisfies the facade intent gate for
/// [`QueryMode::ContextReconstruction`]; any other operation fails that gate
/// as [`ReadError::InvalidIntentOperation`]. The seven candidate provider
/// roles bind to these six reads because the understanding projection serves
/// two roles; role-to-payload projection stays with the owning Governor
/// reconstruction composition, never with this facade.
#[must_use]
pub const fn context_reconstruction_operations() -> [NamedReadOperation; 6] {
    [
        NamedReadOperation::GetTaskState,
        NamedReadOperation::GetAttentionAndProblems,
        NamedReadOperation::GetCurrentEpistemicPosition,
        NamedReadOperation::GetUnderstandingProjectionInputs,
        NamedReadOperation::GetEvidencePack,
        NamedReadOperation::GetCapabilityEvidenceState,
    ]
}

fn validate_dependencies(dependencies: &BTreeMap<RevisionKey, u64>) -> Result<(), ReadError> {
    if dependencies.values().any(|revision| *revision == 0) {
        return Err(ReadError::InvalidDependencyRevision);
    }
    Ok(())
}

fn validate_minimum_revisions(
    heads: &[RevisionHead],
    minimums: &BTreeMap<RevisionKey, u64>,
) -> Result<(), ReadError> {
    for (key, minimum) in minimums {
        let head = heads
            .iter()
            .find(|candidate| candidate.key == *key)
            .ok_or(ReadError::StaleRevision)?;
        if head.revision < *minimum {
            return Err(ReadError::StaleRevision);
        }
    }
    Ok(())
}

fn validate_response_heads(
    response: &NamedReadResponse,
    fence: &StateFence,
) -> Result<(), ReadError> {
    if response
        .revision_heads
        .iter()
        .any(|head| head.state_fence != *fence)
    {
        return Err(ReadError::ResponseMismatch);
    }
    Ok(())
}

fn same_dependency_heads(
    left: &[RevisionHead],
    right: &[RevisionHead],
    dependencies: &BTreeMap<RevisionKey, u64>,
) -> bool {
    dependencies.keys().all(|key| {
        let left_revision = left
            .iter()
            .find(|head| head.key == *key)
            .map(|head| head.revision);
        let right_revision = right
            .iter()
            .find(|head| head.key == *key)
            .map(|head| head.revision);
        left_revision == right_revision
    })
}

fn text(value: &str, field: &'static str) -> Result<(), ReadError> {
    if value.trim().is_empty() {
        return Err(ReadError::EmptyField(field.to_owned()));
    }
    if value.chars().any(char::is_control) {
        return Err(ReadError::InvalidField {
            field: field.to_owned(),
            reason: "control characters are not allowed".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod evidence_pack_read_tests {
    //! T11.1 first behaviour tests for `GetEvidencePack` at the read-facade level.
    //!
    //! `eliot-store-memory` is intentionally *not* a dependency of this crate
    //! (a new dependency would rewrite the workspace lockfile owned by another
    //! lane), so the store side is a minimal in-test [`CanonicalReadClient`]
    //! that enforces the same rules as the production adapters through the
    //! real shared functions: request validation, the generated operation
    //! catalogue gate, fence equality, the declared `subject` / `max_records`
    //! selectors, and the catalogue [`EVIDENCE_PACK_MAX_RECORDS`] bound. Every
    //! asserted record, fence, bound, and truncation value is computed from the
    //! request inputs; nothing is canned and no production logic is altered.

    use std::collections::BTreeMap;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence,
    };
    use eliot_store_api::{
        CanonicalReadClient, EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, NamedReadRequest,
        NamedReadResponse, ReadConsistency, RevisionHead, RevisionKey, ScopeId, StoreError,
        generated_operation_manifests,
    };
    use serde_json::{Value, json};

    use super::*;

    /// Payload-shape version minted by the in-test evidence table below. The
    /// value is local to the test double; the load-bearing assertions compare
    /// request-derived identity, fence, bound, and truncation fields.
    const TEST_EVIDENCE_PACK_VERSION: u32 = 1;

    /// Drives the read facade without an async runtime (this crate has none):
    /// every test future is immediately ready because the in-test client
    /// performs no I/O.
    fn block_on<F: Future>(future: F) -> F::Output {
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

    fn test_epoch(sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
        use std::num::NonZeroU64;
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
        let sequence = NonZeroU64::new(sequence).ok_or(StoreError::InvalidField {
            field: "test.sequence",
            reason: "must be non-zero",
        })?;
        Ok(EpochId::new(lineage, sequence)?)
    }

    fn fence() -> Result<StateFence, Box<dyn std::error::Error>> {
        Ok(StateFence::new(
            test_epoch(1)?,
            ResourceGeneration::genesis(),
        ))
    }

    fn metadata(fence: &StateFence) -> Result<RequestMetadata, Box<dyn std::error::Error>> {
        Ok(RequestMetadata {
            request_id: RequestId::new("request-evidence-1")?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-evidence")?,
            source_id: SourceId::new("source-evidence")?,
            state_fence: fence.clone(),
            clock: ClockReading {
                valid_time_ms: Some(1),
                known_time_ms: Some(1),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
        })
    }

    #[allow(
        clippy::expect_used,
        reason = "test-only closed selectors are statically known valid"
    )]
    fn evidence_params(subject: &str, max_records: &str) -> NamedParameters {
        NamedParameters::from_map(BTreeMap::from([
            ("subject".to_owned(), Value::String(subject.to_owned())),
            (
                "max_records".to_owned(),
                Value::String(max_records.to_owned()),
            ),
        ]))
        .expect("evidence selectors are closed and bounded")
    }

    fn verification_intent() -> QueryIntent {
        QueryIntent {
            mode: QueryMode::Verification,
            time_scope: TimeScope::EvidenceWindow,
            branch_environment_scope: BranchEnvironmentScope::LocalEnvironment,
            freshness_policy: FreshnessPolicy::ExactCapturedRecords,
            required_assurance: RequiredAssurance::VerifierEvidence,
        }
    }

    fn evidence_query(
        scope: Option<&str>,
        consistency: ReadConsistency,
        dependencies: BTreeMap<RevisionKey, u64>,
        parameters: NamedParameters,
    ) -> Result<QueryRequest, StoreError> {
        Ok(QueryRequest {
            intent: verification_intent(),
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: scope.map(ScopeId::new).transpose()?,
            consistency,
            dependency_revisions: dependencies,
            ordering: ReadOrderingBinding::without_order_dependency(),
            parameters,
            provenance_handles: Vec::new(),
        })
    }

    fn pack_records(payload: &Value) -> Result<&Vec<Value>, StoreError> {
        payload
            .get("records")
            .and_then(Value::as_array)
            .ok_or(StoreError::Empty {
                field: "evidence.records",
            })
    }

    fn pack_provenance(payload: &Value) -> Result<&serde_json::Map<String, Value>, StoreError> {
        payload
            .get("provenance")
            .and_then(Value::as_object)
            .ok_or(StoreError::Empty {
                field: "evidence.provenance",
            })
    }

    /// Minimal in-test evidence table. It stores captured subjects in capture
    /// order and derives every response field from the incoming request using
    /// the same rule order as the production adapters: request validation,
    /// catalogue gate, fence equality, scope declaration, selector shape, and
    /// the explicit bound.
    struct EvidenceTableClient {
        fence: StateFence,
        captured: Vec<String>,
    }

    impl EvidenceTableClient {
        fn new(fence: StateFence) -> Self {
            Self {
                fence,
                captured: Vec::new(),
            }
        }

        fn capture(&mut self, subject: &str) {
            self.captured.push(subject.to_owned());
        }
    }

    impl CanonicalReadClient for EvidenceTableClient {
        async fn revision_heads(
            &self,
            keys: Vec<RevisionKey>,
        ) -> Result<Vec<RevisionHead>, StoreError> {
            keys.into_iter()
                .map(|key| {
                    Ok(RevisionHead {
                        key,
                        revision: 1,
                        state_fence: self.fence.clone(),
                    })
                })
                .collect()
        }

        async fn execute_named(
            &self,
            request: NamedReadRequest,
        ) -> Result<NamedReadResponse, StoreError> {
            request.validate()?;
            if request.operation != NamedReadOperation::GetEvidencePack {
                return Err(StoreError::UnknownOperation);
            }
            // Same pre-dispatch gate both production adapters apply.
            let entries = generated_operation_manifests()?;
            request.validate_against_catalogue(&entries)?;
            if request.state_fence != self.fence {
                return Err(StoreError::FenceMismatch);
            }
            // The catalogue gate already enforces the scope declaration;
            // re-check fail-closed so this arm never depends on call order.
            let scope_id = request.scope_id.clone().ok_or(StoreError::InvalidField {
                field: "scope_id",
                reason: "evidence pack read requires scope_id",
            })?;
            let subject = request
                .parameters
                .get("subject")
                .and_then(Value::as_str)
                .ok_or(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "missing required parameter",
                })?;
            if subject.trim().is_empty() || subject.chars().any(char::is_control) {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "subject must be a non-blank string",
                });
            }
            let bound_raw = request
                .parameters
                .get("max_records")
                .and_then(Value::as_str)
                .ok_or(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "missing required parameter",
                })?;
            let max_records: u32 = bound_raw.parse().map_err(|_| StoreError::InvalidField {
                field: "operation.parameter",
                reason: "max_records must be a positive decimal bound",
            })?;
            if max_records == 0 {
                return Err(StoreError::InvalidField {
                    field: "operation.parameter",
                    reason: "max_records must be a positive decimal bound",
                });
            }
            if max_records > EVIDENCE_PACK_MAX_RECORDS {
                return Err(StoreError::PayloadTooLarge);
            }
            let limit = usize::try_from(max_records).map_err(|_| StoreError::PayloadTooLarge)?;
            let matched: Vec<usize> = self
                .captured
                .iter()
                .enumerate()
                .filter(|(_, captured)| captured.as_str() == subject)
                .map(|(index, _)| index)
                .collect();
            let matched_total = matched.len();
            let records: Vec<Value> = matched
                .into_iter()
                .take(limit)
                .map(|index| {
                    json!({
                        "capture_index": index,
                        "operation": "CaptureObservation",
                        "subject": self.captured[index],
                    })
                })
                .collect();
            let returned = records.len();
            let payload = json!({
                "version": TEST_EVIDENCE_PACK_VERSION,
                "subject": subject,
                "scope_id": scope_id.as_str(),
                "records": records,
                "provenance": {
                    "state_fence": self.fence,
                    "matched_total": matched_total,
                    "returned": returned,
                    "max_records": max_records,
                    "truncated": matched_total > returned,
                },
            });
            let response = NamedReadResponse {
                operation: request.operation,
                state_fence: self.fence.clone(),
                revision_heads: vec![RevisionHead {
                    key: RevisionKey::new(format!("scope:{scope_id}"))?,
                    revision: 1,
                    state_fence: self.fence.clone(),
                }],
                payload,
            };
            response.validate()?;
            Ok(response)
        }
    }

    #[test]
    fn evidence_pack_query_request_validates_for_verification_intent()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = evidence_query(
            Some("scope-evidence"),
            ReadConsistency::Eventual,
            BTreeMap::new(),
            evidence_params("evidence-alpha", "10"),
        )?;
        request.validate()?;
        Ok(())
    }

    #[test]
    fn evidence_pack_query_request_rejects_wrong_intent_and_missing_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut request = evidence_query(
            Some("scope-evidence"),
            ReadConsistency::Eventual,
            BTreeMap::new(),
            evidence_params("evidence-alpha", "10"),
        )?;
        request.intent.mode = QueryMode::CurrentPosition;
        assert!(matches!(
            request.validate(),
            Err(ReadError::InvalidIntentOperation { .. })
        ));

        let unscoped = evidence_query(
            None,
            ReadConsistency::Eventual,
            BTreeMap::new(),
            evidence_params("evidence-alpha", "10"),
        )?;
        assert!(matches!(unscoped.validate(), Err(ReadError::ScopeRequired)));
        Ok(())
    }

    #[test]
    fn evidence_pack_state_context_rejects_non_state_operation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = fence()?;
        let ctx = metadata(&fence)?;
        let service = ReadService::new(EvidenceTableClient::new(fence));
        let request = StateRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(ScopeId::new("scope-evidence")?),
            consistency: ReadConsistency::Eventual,
            dependency_revisions: BTreeMap::new(),
            ordering: ReadOrderingBinding::without_order_dependency(),
            parameters: evidence_params("evidence-alpha", "10"),
            provenance_handles: Vec::new(),
        };
        let result = block_on(service.state(&ctx, request));
        assert!(
            matches!(result, Err(ReadError::OperationNotAllowed { context, .. }) if context == "state")
        );
        Ok(())
    }

    #[test]
    fn evidence_pack_query_returns_exact_record_through_closed_selectors()
    -> Result<(), Box<dyn std::error::Error>> {
        // T11.1 (#1465 residual fix, #1144 wire): the closed catalogue admits
        // only `subject`/`max_records` for `GetEvidencePack`; the facade
        // forwards exactly those closed selectors. There is no free-text
        // query field: the operation plus selectors fully determine the read.
        let fence = fence()?;
        let ctx = metadata(&fence)?;
        let mut client = EvidenceTableClient::new(fence.clone());
        client.capture("evidence-alpha");
        let service = ReadService::new(client);
        let request = evidence_query(
            Some("scope-evidence"),
            ReadConsistency::Eventual,
            BTreeMap::new(),
            evidence_params("evidence-alpha", "10"),
        )?;
        let result = block_on(service.query(&ctx, request))?;
        assert_eq!(result.operation, NamedReadOperation::GetEvidencePack);
        assert_eq!(result.state_fence, fence);
        assert_eq!(
            result.payload.get("subject").and_then(Value::as_str),
            Some("evidence-alpha")
        );
        let records = pack_records(&result.payload)?;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].get("subject").and_then(Value::as_str),
            Some("evidence-alpha")
        );
        let provenance = pack_provenance(&result.payload)?;
        assert_eq!(
            provenance.get("matched_total").and_then(Value::as_u64),
            Some(1)
        );
        Ok(())
    }

    #[test]
    fn evidence_pack_query_rejects_reserved_selector_keys() -> Result<(), Box<dyn std::error::Error>>
    {
        // #1465 residual preserved, #1144 wire: a caller that smuggles the
        // retired top-level selector names (`query`, `exact_resource_uri`) as
        // store parameters still fails closed at construction — success
        // would mean the boundary silently widened.
        let mut smuggled = evidence_params("evidence-alpha", "10").into_inner();
        smuggled.insert("query".to_owned(), Value::String("free text".to_owned()));
        assert!(
            matches!(
                NamedParameters::from_map(smuggled),
                Err(ReadError::DuplicateField(field)) if field == "named_parameters"
            ),
            "smuggled query param must fail closed"
        );

        let mut smuggled_uri = evidence_params("evidence-alpha", "10").into_inner();
        smuggled_uri.insert(
            "exact_resource_uri".to_owned(),
            Value::String("eliot://resource/1".to_owned()),
        );
        assert!(
            matches!(
                NamedParameters::from_map(smuggled_uri),
                Err(ReadError::DuplicateField(field)) if field == "named_parameters"
            ),
            "smuggled exact_resource_uri param must fail closed"
        );
        // Exact expansion uses `ResourceRequest`, never `QueryRequest`: there
        // is no request-level URI field left to smuggle through, and the
        // well-formed request still validates.
        let request = evidence_query(
            Some("scope-evidence"),
            ReadConsistency::Eventual,
            BTreeMap::new(),
            evidence_params("evidence-alpha", "10"),
        )?;
        request.validate()?;
        Ok(())
    }

    #[test]
    fn evidence_pack_query_refuses_changed_fence_and_over_bound_request()
    -> Result<(), Box<dyn std::error::Error>> {
        // T11.1 acceptance: changing the fence or exceeding the declared bound
        // must not return a successful current view.
        let fence = fence()?;
        let service = ReadService::new(EvidenceTableClient::new(fence.clone()));

        let changed = StateFence::new(test_epoch(2)?, ResourceGeneration::genesis());
        let changed_ctx = metadata(&changed)?;
        let fenced = evidence_query(
            Some("scope-evidence"),
            ReadConsistency::Eventual,
            BTreeMap::new(),
            evidence_params("evidence-alpha", "10"),
        )?;
        assert!(block_on(service.query(&changed_ctx, fenced)).is_err());

        let over_bound = (EVIDENCE_PACK_MAX_RECORDS + 1).to_string();
        let mut dependencies = BTreeMap::new();
        dependencies.insert(RevisionKey::new("scope:scope-evidence")?, 1);
        let bounded = evidence_query(
            Some("scope-evidence"),
            ReadConsistency::ExactFence,
            dependencies,
            evidence_params("evidence-alpha", &over_bound),
        )?;
        let ctx = metadata(&fence)?;
        assert!(block_on(service.query(&ctx, bounded)).is_err());
        Ok(())
    }

    #[test]
    fn evidence_pack_store_rules_derive_identity_fence_and_provenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = fence()?;
        let mut client = EvidenceTableClient::new(fence.clone());
        client.capture("evidence-alpha");
        client.capture("evidence-beta");
        client.capture("evidence-alpha");
        let request = NamedReadRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(ScopeId::new("scope-evidence")?),
            consistency: ReadConsistency::Eventual,
            state_fence: fence.clone(),
            parameters: evidence_params("evidence-alpha", "10").into_inner(),
        };
        let response = block_on(client.execute_named(request))?;
        assert_eq!(response.operation, NamedReadOperation::GetEvidencePack);
        assert_eq!(response.state_fence, fence);
        let payload = &response.payload;
        assert_eq!(
            payload.get("subject").and_then(Value::as_str),
            Some("evidence-alpha")
        );
        assert_eq!(
            payload.get("version").and_then(Value::as_u64),
            Some(u64::from(TEST_EVIDENCE_PACK_VERSION))
        );
        let records = pack_records(payload)?;
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].get("capture_index").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            records[1].get("capture_index").and_then(Value::as_u64),
            Some(2)
        );
        for record in records {
            assert_eq!(
                record.get("operation").and_then(Value::as_str),
                Some("CaptureObservation")
            );
            assert_eq!(
                record.get("subject").and_then(Value::as_str),
                Some("evidence-alpha")
            );
        }
        let provenance = pack_provenance(payload)?;
        assert_eq!(
            provenance.get("matched_total").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(provenance.get("returned").and_then(Value::as_u64), Some(2));
        assert_eq!(
            provenance.get("max_records").and_then(Value::as_u64),
            Some(10)
        );
        assert_eq!(
            provenance.get("truncated").and_then(Value::as_bool),
            Some(false)
        );
        let expected_fence = serde_json::to_value(&fence)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        assert_eq!(provenance.get("state_fence"), Some(&expected_fence));
        Ok(())
    }

    #[test]
    fn evidence_pack_store_rules_truncate_empty_and_refuse()
    -> Result<(), Box<dyn std::error::Error>> {
        let fence = fence()?;
        let mut client = EvidenceTableClient::new(fence.clone());
        client.capture("evidence-alpha");
        client.capture("evidence-alpha");

        let exact = |subject: &str, max_records: &str, fence: &StateFence| {
            Ok::<_, StoreError>(NamedReadRequest {
                operation: NamedReadOperation::GetEvidencePack,
                scope_id: Some(ScopeId::new("scope-evidence")?),
                consistency: ReadConsistency::Eventual,
                state_fence: fence.clone(),
                parameters: evidence_params(subject, max_records).into_inner(),
            })
        };

        // Truncation is computed from the inputs with a visible marker.
        let response = block_on(client.execute_named(exact("evidence-alpha", "1", &fence)?))?;
        let records = pack_records(&response.payload)?;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].get("capture_index").and_then(Value::as_u64),
            Some(0)
        );
        let provenance = pack_provenance(&response.payload)?;
        assert_eq!(
            provenance.get("matched_total").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(provenance.get("returned").and_then(Value::as_u64), Some(1));
        assert_eq!(
            provenance.get("truncated").and_then(Value::as_bool),
            Some(true)
        );

        // An unknown subject is an exact empty result, not an error.
        let response =
            block_on(client.execute_named(exact("evidence-never-captured", "10", &fence)?))?;
        let records = pack_records(&response.payload)?;
        assert!(records.is_empty());
        let provenance = pack_provenance(&response.payload)?;
        assert_eq!(
            provenance.get("matched_total").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(provenance.get("returned").and_then(Value::as_u64), Some(0));
        assert_eq!(
            provenance.get("truncated").and_then(Value::as_bool),
            Some(false)
        );

        // Over-bound, malformed bound, wrong fence, and missing scope refuse typed.
        let over_bound = (EVIDENCE_PACK_MAX_RECORDS + 1).to_string();
        assert_eq!(
            block_on(client.execute_named(exact("evidence-alpha", &over_bound, &fence)?)),
            Err(StoreError::PayloadTooLarge)
        );
        assert!(matches!(
            block_on(client.execute_named(exact("evidence-alpha", "0", &fence)?)),
            Err(StoreError::InvalidField { .. })
        ));
        assert!(matches!(
            block_on(client.execute_named(exact("evidence-alpha", "ten", &fence)?)),
            Err(StoreError::InvalidField { .. })
        ));
        let changed = StateFence::new(test_epoch(2)?, ResourceGeneration::genesis());
        assert_eq!(
            block_on(client.execute_named(exact("evidence-alpha", "10", &changed)?)),
            Err(StoreError::FenceMismatch)
        );
        let mut unscoped = exact("evidence-alpha", "10", &fence)?;
        unscoped.scope_id = None;
        assert!(matches!(
            block_on(client.execute_named(unscoped)),
            Err(StoreError::InvalidField {
                field: "scope_id",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn local_port_evidence_query_returns_exact_record() -> Result<(), Box<dyn std::error::Error>> {
        // HANDOFF-LRR-GOV Query cut: the port returns the exact record and
        // provenance live through `ReadService::query`.
        let fence = fence()?;
        let ctx = metadata(&fence)?;
        let mut client = EvidenceTableClient::new(fence.clone());
        client.capture("evidence-alpha");
        let service = ReadService::new(client);
        let scope = ScopeId::new("scope-evidence")?;
        let result =
            block_on(service.evidence_query(&ctx, scope, "evidence-alpha".to_owned(), 10))?;
        assert_eq!(result.operation, NamedReadOperation::GetEvidencePack);
        assert_eq!(result.state_fence, fence);
        assert_eq!(result.consistency, ReadConsistency::Eventual);
        assert_eq!(
            result.payload.get("subject").and_then(Value::as_str),
            Some("evidence-alpha")
        );
        let records = pack_records(&result.payload)?;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].get("subject").and_then(Value::as_str),
            Some("evidence-alpha")
        );
        let provenance = pack_provenance(&result.payload)?;
        assert_eq!(
            provenance.get("matched_total").and_then(Value::as_u64),
            Some(1)
        );
        Ok(())
    }

    #[test]
    fn local_port_refuses_wrong_fence_over_bound_and_unactivated_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        // HANDOFF-LRR-GOV fail-closed cut: a wrong fence or an over-bound
        // request never returns success, and projection inputs stay
        // `Unavailable` (never `Ok`-empty, never canned) until MGR04 (#19)
        // activates the storage operation.
        let fence = fence()?;
        let ctx = metadata(&fence)?;
        let service = ReadService::new(EvidenceTableClient::new(fence.clone()));

        let changed = StateFence::new(test_epoch(2)?, ResourceGeneration::genesis());
        let changed_ctx = metadata(&changed)?;
        let scope = ScopeId::new("scope-evidence")?;
        assert!(
            block_on(service.evidence_query(
                &changed_ctx,
                scope.clone(),
                "evidence-alpha".to_owned(),
                10,
            ))
            .is_err()
        );

        let over_bound = EVIDENCE_PACK_MAX_RECORDS + 1;
        assert!(
            block_on(service.evidence_query(
                &ctx,
                scope.clone(),
                "evidence-alpha".to_owned(),
                over_bound,
            ))
            .is_err()
        );

        match block_on(service.projection_inputs(&ctx, scope, None, Vec::new())) {
            Err(ReadError::Store(StoreReadFailure::Unavailable)) => {}
            other => panic!("projection inputs must fail closed Unavailable, observed: {other:?}"),
        }
        Ok(())
    }
}
