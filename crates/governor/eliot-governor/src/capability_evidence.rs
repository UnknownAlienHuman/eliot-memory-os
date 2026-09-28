//! Scoped capability evidence registry (Issue #1957, I3.4).
//!
//! Capability is not a boolean. Each claim carries status, source, a complete
//! route-scope fingerprint, limitations/negative evidence, references,
//! observed time, and expiry. Legacy declarations enter only as
//! `declared` / `imported_legacy_declaration` (via
//! [`eliot_config::legacy_capability_import`]) and never satisfy production
//! admission. Production admission requires fresh exact-fingerprint
//! `probe_passed` or `observed` evidence from an evidence source (never a
//! legacy import, never a bare failure report); exact-fingerprint `broken`,
//! `unsupported`, or `degraded` evidence restricts production work. A runtime,
//! adapter, provider, serializer, or behavior-affecting profile change stales
//! dependent evidence through a narrowed dependency selector.
//!
//! Keying: records are keyed on `skill_id`, the same key the canonical
//! evidence read uses. `GetCapabilityEvidenceState` selects by exact
//! `skill_id` + `max_records`, as do the `ApplyLifecyclePolicy` lifecycle
//! transitions it reports. There is no parallel free-form capability
//! namespace.
//!
//! Staleness is derived, never persisted: a record is fresh only while its
//! `observed_at` is not in the future, its `expires_at` (when present) is
//! unreached at the caller-supplied observation time, and its scope
//! fingerprint is absent from the registry invalidation set. Time therefore
//! flows into every admission decision through the explicit `now` parameter,
//! so positive evidence can go stale in a running daemon.
//!
//! Scope keying (issue #1958): [`RouteScopeFingerprint`] is the *complete
//! effective* route identity, not a provider/model label. It carries every
//! behaviour-changing group of the I3.4 `RouteFingerprint` - host family,
//! adapter identity, protocol/transport, runtime and adapter hashes, OS
//! architecture, auth profile, provider/model route, tool-call ID and role
//! ordering, reasoning continuation/compaction, and the serializer plus
//! behaviour-affecting feature-flag and tool/context profile hashes - so two
//! attempts differing only by serializer or by tool-call/role ordering resolve
//! to different keys and cannot reuse each other's capability evidence. A
//! dimension the source does not expose stays `None` (unknown) and matches
//! only `None`; it is never back-filled from the requested route.
//!
//! Supersession is decided by the immutable owner-issued revision of the
//! evidence, never by arrival order or by a locally observed wall clock: the
//! registry holds one [`RetainedCapabilityEvidence`] per
//! `(skill_id, scope_fingerprint)` key, and an insertion replaces it only when
//! its [`OwnerEvidenceRevision`] is strictly newer. A delayed replay is
//! refused whole, so it displaces no record and clears no invalidation.
//!
//! The owner-issued revision is the value the canonical store arbitrates for
//! the evidence key (the owner presents the expected predecessor on commit and
//! the store issues the successor), paired with the exact owner-issued
//! evidence reference of the committed record bytes. `observed_at` remains
//! record *content* for the I3.4 shape and the time-freshness predicate, and
//! deliberately carries no supersession authority: a delayed writer controls
//! its own clock reading, so a locally compared `observed_at` is not owner
//! authority.
//!
//! Invalidation is cleared only through a fresh requalification that names
//! the blocking evidence reference and is strictly newer than it. The registry
//! retains that [`InvalidationCause`] per invalidated scope, so a known
//! restriction or an applied scope change is not erased by an unrelated
//! record, by a delayed replay, or by qualifying evidence that does not
//! reference the failure or change it resolves. The registry never evicts a
//! key's latest frontier: after the bound is reached, new keys are refused,
//! and an unretained restriction fails production admission closed. An empty
//! registry still refuses rather than admits.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use eliot_config::legacy_capability_import::ImportedLegacyEvidence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum retained evidence records. New keys beyond this bound are refused
/// so no retained key's supersession frontier can be erased.
pub const MAX_CAPABILITY_EVIDENCE_RECORDS: usize = 512;

/// Owner-issued reserved revision floor for a legacy `declared` /
/// `imported_legacy_declaration` record.
///
/// A legacy declaration is not evidence and no canonical store arbitrates a
/// revision for it, so it is pinned at a reserved floor instead of being given
/// a synthetic ordering value. Because every store-issued revision is at least
/// `1` and same-key insertion requires a strictly newer revision, a legacy
/// record can never displace, reorder, or requalify verified evidence, and a
/// replay of the same legacy declaration converges instead of superseding.
pub const LEGACY_DECLARED_OWNER_REVISION: u64 = 0;

/// Returns true when `value` is exactly one lowercase hex SHA-256 digest.
///
/// An owner-issued evidence reference is a presented digest of the committed
/// record bytes; the shape is checked here so a malformed or forged reference
/// is refused at the owner boundary instead of becoming an invalidation cause
/// no requalification can ever match.
#[must_use]
pub fn is_evidence_ref(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Rejected owner-issued revision and requalification identities.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EvidenceRevisionError {
    /// The store never issues revision zero; only the reserved legacy floor
    /// may hold it.
    #[error("owner-issued capability evidence revision must be at least 1")]
    RevisionBelowFloor,
    /// The evidence reference is not one presented digest.
    #[error("owner-issued capability evidence reference must be one hex SHA-256 digest")]
    MalformedEvidenceRef,
    /// A requalification must name the blocking evidence reference exactly.
    #[error("requalification reference must be one hex SHA-256 digest")]
    MalformedRequalificationRef,
}

/// Immutable owner-issued revision identity of one retained evidence record.
///
/// `owner_revision` is the monotonic revision the canonical store arbitrates
/// for the `(skill_id, scope_fingerprint)` evidence key: the owner presents the
/// expected predecessor on commit and the store issues the successor, so a
/// delayed writer holding a stale predecessor is refused by the store before it
/// can reach this registry. `evidence_ref` is the exact owner-issued reference
/// of the committed record bytes, which the store echoes verbatim on readback.
///
/// This pair is the only supersession authority in the registry. It is never
/// derived from a locally observed instant.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct OwnerEvidenceRevision {
    /// Store-issued monotonic revision for this evidence key.
    pub owner_revision: u64,
    /// Presented digest of the committed record bytes.
    pub evidence_ref: String,
}

impl OwnerEvidenceRevision {
    /// Builds one store-issued evidence revision.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceRevisionError::RevisionBelowFloor`] for a revision
    /// below `1` (only [`LEGACY_DECLARED_OWNER_REVISION`] is reserved and it
    /// is minted by [`OwnerEvidenceRevision::legacy_declared`]) and
    /// [`EvidenceRevisionError::MalformedEvidenceRef`] for a reference that is
    /// not one hex SHA-256 digest.
    pub fn issued(owner_revision: u64, evidence_ref: &str) -> Result<Self, EvidenceRevisionError> {
        if owner_revision < 1 {
            return Err(EvidenceRevisionError::RevisionBelowFloor);
        }
        if !is_evidence_ref(evidence_ref) {
            return Err(EvidenceRevisionError::MalformedEvidenceRef);
        }
        Ok(Self {
            owner_revision,
            evidence_ref: evidence_ref.to_owned(),
        })
    }

    /// Returns the reserved floor revision for a legacy `declared` record.
    ///
    /// The reference is a fixed digest over the reserved legacy marker rather
    /// than the record bytes: a legacy declaration is not owner-issued
    /// evidence, so its reference names the reservation, not a commit.
    #[must_use]
    pub fn legacy_declared() -> Self {
        Self {
            owner_revision: LEGACY_DECLARED_OWNER_REVISION,
            evidence_ref: eliot_store_api::sha256_hex(
                b"eliot.capability.evidence.reserved.legacy-declared",
            ),
        }
    }

    /// Returns true when this is the reserved legacy-declared floor.
    #[must_use]
    pub const fn is_legacy_declared(&self) -> bool {
        self.owner_revision == LEGACY_DECLARED_OWNER_REVISION
    }
}

/// Why one scope fingerprint is currently invalidated.
///
/// Retained with the invalidation so a requalification can be required to name
/// the exact blocking evidence reference and to be strictly newer than it,
/// instead of any qualifying record clearing the restriction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidationCause {
    /// The owner-issued evidence reference, or owner-issued change reference,
    /// that produced this invalidation. A requalification must name it
    /// exactly.
    pub blocking_evidence_ref: String,
    /// The owner-issued revision at which the blocking evidence or change was
    /// issued. A requalification must be strictly newer than it.
    pub blocking_revision: OwnerEvidenceRevision,
}

impl InvalidationCause {
    /// Builds one retained invalidation cause from an owner-issued reference
    /// and the owner-issued revision that produced it.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceRevisionError::MalformedEvidenceRef`] when the
    /// blocking reference is not one hex SHA-256 digest.
    pub fn new(
        blocking_evidence_ref: &str,
        blocking_revision: OwnerEvidenceRevision,
    ) -> Result<Self, EvidenceRevisionError> {
        if !is_evidence_ref(blocking_evidence_ref) {
            return Err(EvidenceRevisionError::MalformedEvidenceRef);
        }
        Ok(Self {
            blocking_evidence_ref: blocking_evidence_ref.to_owned(),
            blocking_revision,
        })
    }
}

/// One retained evidence record together with its immutable owner-issued
/// revision identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedCapabilityEvidence {
    /// The retained record.
    pub record: CapabilityEvidenceRecord,
    /// The owner-issued revision identity that orders this key.
    pub revision: OwnerEvidenceRevision,
}

/// Claim status for one scoped capability record.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Declared,
    ProbePassed,
    Observed,
    Degraded,
    Broken,
    Unsupported,
    Unknown,
}

/// Provenance of one scoped capability record.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySource {
    OfficialContract,
    RuntimeHandshake,
    ActiveProbe,
    ProductionObservation,
    SourceInspection,
    ReproducedFailure,
    ImportedLegacyDeclaration,
}

impl CapabilitySource {
    /// Returns whether this source can carry production-admitting evidence.
    ///
    /// Admissibility is a property of the source, not the status: a legacy
    /// import or a bare failure report never admits production work, even
    /// when paired with a positive status.
    #[must_use]
    pub const fn is_admissible_evidence(self) -> bool {
        matches!(
            self,
            Self::OfficialContract
                | Self::RuntimeHandshake
                | Self::ActiveProbe
                | Self::ProductionObservation
                | Self::SourceInspection
        )
    }
}

/// Complete route-scope fingerprint for one capability claim.
///
/// This is the *complete effective* route identity issue #1958 requires, not a
/// provider/model label: every behaviour-changing group I3.4 lists in
/// `RouteFingerprint` is present, so a route that differs only in host family,
/// adapter identity, protocol/transport, tool-call ID and role ordering, or
/// reasoning continuation/compaction moves the key and its dependent evidence
/// stops matching instead of being reused. It is the same value the
/// [`RouteBehaviorFingerprint`](crate::RouteBehaviorFingerprint) owner
/// projects, so capability lookup cannot drift from route identity.
///
/// Fields the source cannot provide stay `None` (unknown, never inferred from
/// the requested route, a UI selection, or prompt text). `None` matches only
/// `None` during exact-fingerprint comparison.
/// `Ord` is derived so a scope fingerprint can key the ordered invalidation
/// map. Field order is the declaration order, so the derived order is a stable
/// total order over scopes; it is used only as map key order, never as an
/// evidence-age or authority comparison.
#[derive(
    Clone, Debug, Default, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct RouteScopeFingerprint {
    pub host_family: Option<String>,
    pub adapter_id: Option<String>,
    /// Protocol kind and transport kind of the runtime connection.
    pub protocol_transport: Option<String>,
    pub runtime_hash: Option<String>,
    pub adapter_hash: Option<String>,
    pub os_architecture: Option<String>,
    pub auth_profile_class: Option<String>,
    /// Requested provider and model route label, exposed by the runtime.
    pub provider_model_route: Option<String>,
    /// Tool-call ID and role ordering semantics of the adapter.
    pub tool_call_id_and_role_ordering: Option<String>,
    /// Reasoning continuation and compaction behavior of the runtime.
    pub reasoning_continuation_and_compaction: Option<String>,
    /// Composite of the runtime-exposed message serializer/chat-template
    /// fingerprint and the behaviour-affecting feature-flag and tool/context
    /// profile hashes of the installation.
    pub feature_flags_and_serializer: Option<String>,
}

impl RouteScopeFingerprint {
    /// Returns true when every fingerprint field is exactly equal.
    #[must_use]
    pub fn exact_match(&self, other: &Self) -> bool {
        self == other
    }

    /// Returns the exact owner-issued reference of this one behaviour scope.
    ///
    /// The reference is a digest over the canonical bytes of the complete
    /// effective route identity, so it changes exactly when the scope changes
    /// and is stable for one scope across processes. It is the immutable
    /// reference a dependent-scope change is recorded under and that a
    /// requalification of the changed scope can name.
    #[must_use]
    pub fn reference_digest(&self) -> String {
        let bytes = eliot_store_api::canonical_json_bytes(self)
            .unwrap_or_else(|_| panic!("RouteScopeFingerprint is always canonically encodable"));
        eliot_store_api::sha256_hex(&bytes)
    }
}

/// Narrows a scope change to the dependency dimensions that actually moved.
///
/// A runtime, adapter, provider, serializer, or behavior-affecting profile
/// change stales only the evidence depending on a selected dimension; routes
/// and accounts whose selected fields still match the current fingerprint
/// stay admitted. [`ScopeDependencySelector::all`] reproduces the coarse
/// whole-fingerprint invalidation for callers that cannot attribute the
/// change more narrowly. Eleven independent dependency dimensions stay eleven
/// explicit flags (not a bitmask) so each contract dimension reads by name.
#[allow(
    clippy::struct_excessive_bools,
    reason = "eleven named I03-04 dependency dimensions"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeDependencySelector {
    pub host_family: bool,
    pub adapter_id: bool,
    pub protocol_transport: bool,
    pub runtime_hash: bool,
    pub adapter_hash: bool,
    pub os_architecture: bool,
    pub auth_profile_class: bool,
    pub provider_model_route: bool,
    pub tool_call_id_and_role_ordering: bool,
    pub reasoning_continuation_and_compaction: bool,
    pub feature_flags_and_serializer: bool,
}

impl ScopeDependencySelector {
    /// Selects every dependency dimension (coarse whole-scope invalidation).
    #[must_use]
    pub const fn all() -> Self {
        Self {
            host_family: true,
            adapter_id: true,
            protocol_transport: true,
            runtime_hash: true,
            adapter_hash: true,
            os_architecture: true,
            auth_profile_class: true,
            provider_model_route: true,
            tool_call_id_and_role_ordering: true,
            reasoning_continuation_and_compaction: true,
            feature_flags_and_serializer: true,
        }
    }

    /// Selects no dimension; application stales nothing.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            host_family: false,
            adapter_id: false,
            protocol_transport: false,
            runtime_hash: false,
            adapter_hash: false,
            os_architecture: false,
            auth_profile_class: false,
            provider_model_route: false,
            tool_call_id_and_role_ordering: false,
            reasoning_continuation_and_compaction: false,
            feature_flags_and_serializer: false,
        }
    }

    /// Returns true when `record` differs from `current` on at least one
    /// selected dimension.
    #[must_use]
    pub fn selects_difference(
        &self,
        record: &RouteScopeFingerprint,
        current: &RouteScopeFingerprint,
    ) -> bool {
        (self.host_family && record.host_family != current.host_family)
            || (self.adapter_id && record.adapter_id != current.adapter_id)
            || (self.protocol_transport && record.protocol_transport != current.protocol_transport)
            || (self.runtime_hash && record.runtime_hash != current.runtime_hash)
            || (self.adapter_hash && record.adapter_hash != current.adapter_hash)
            || (self.os_architecture && record.os_architecture != current.os_architecture)
            || (self.auth_profile_class && record.auth_profile_class != current.auth_profile_class)
            || (self.provider_model_route
                && record.provider_model_route != current.provider_model_route)
            || (self.tool_call_id_and_role_ordering
                && record.tool_call_id_and_role_ordering != current.tool_call_id_and_role_ordering)
            || (self.reasoning_continuation_and_compaction
                && record.reasoning_continuation_and_compaction
                    != current.reasoning_continuation_and_compaction)
            || (self.feature_flags_and_serializer
                && record.feature_flags_and_serializer != current.feature_flags_and_serializer)
    }
}

/// Rejected verified-evidence relations: the `verified` constructor admits
/// only status/source pairs that real evidence can carry.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EvidenceRelationError {
    /// `declared` enters only through the legacy importer, never as verified
    /// evidence.
    #[error("declared status enters only through the legacy importer")]
    DeclaredIsLegacyOnly,
    /// `unknown` is not verified evidence of anything.
    #[error("unknown status is never verified evidence")]
    UnknownIsNeverVerified,
    /// Legacy declarations are never verified evidence, even for positive
    /// statuses.
    #[error("imported legacy declarations never carry verified evidence")]
    LegacySourceNeverVerified,
    /// A bare failure report never carries positive evidence.
    #[error("reproduced failures never carry probe_passed or observed evidence")]
    FailureSourceNeverPositive,
    /// This status cannot be observed from this source.
    #[error("status cannot be evidenced by this source")]
    StatusSourceMismatch,
}

/// One evidence-linked capability fact in the canonical registry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEvidenceRecord {
    /// Skill identity: the same key the `GetCapabilityEvidenceState` read
    /// and the `ApplyLifecyclePolicy` transitions it reports use.
    pub skill_id: String,
    pub status: CapabilityStatus,
    pub source: CapabilitySource,
    /// Complete route-scope fingerprint, per the I03-04 contract shape.
    pub scope_fingerprint: RouteScopeFingerprint,
    pub limitations_and_negative_evidence: Vec<String>,
    pub evidence_refs: Vec<String>,
    /// The exact owner-issued evidence reference this record requalifies: the
    /// reference of the restriction, or of the applied dependency change, that
    /// this fresh evidence resolves.
    ///
    /// `None` for a first observation and for every legacy `declared` record.
    /// A qualifying record clears a scope invalidation only when it names the
    /// retained [`InvalidationCause`] exactly, so positive evidence that never
    /// observed the failure or the change cannot silently revive a restricted
    /// scope.
    pub requalification: Option<String>,
    pub observed_at: u64,
    pub expires_at: Option<u64>,
}

impl CapabilityEvidenceRecord {
    /// Builds a verified-evidence record (probe/observation path).
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceRelationError`] when the status/source pair cannot
    /// occur as real evidence: `declared` and `unknown` never verify, the
    /// legacy source never verifies, a failure report never carries positive
    /// evidence, and each status verifies only through its evidence sources
    /// (`probe_passed` via contract/handshake/probe/inspection, `observed`
    /// via contract/handshake/production observation, `degraded` via
    /// handshake/probe/production observation, `broken`/`unsupported` via
    /// probe/failure report).
    pub fn verified(
        skill_id: &str,
        status: CapabilityStatus,
        source: CapabilitySource,
        scope_fingerprint: RouteScopeFingerprint,
        observed_at: u64,
    ) -> Result<Self, EvidenceRelationError> {
        if skill_id.trim().is_empty() || skill_id.chars().any(char::is_control) {
            return Err(EvidenceRelationError::StatusSourceMismatch);
        }
        let admissible = match status {
            CapabilityStatus::Declared => return Err(EvidenceRelationError::DeclaredIsLegacyOnly),
            CapabilityStatus::Unknown => return Err(EvidenceRelationError::UnknownIsNeverVerified),
            CapabilityStatus::ProbePassed => matches!(
                source,
                CapabilitySource::OfficialContract
                    | CapabilitySource::RuntimeHandshake
                    | CapabilitySource::ActiveProbe
                    | CapabilitySource::SourceInspection
            ),
            CapabilityStatus::Observed => matches!(
                source,
                CapabilitySource::OfficialContract
                    | CapabilitySource::RuntimeHandshake
                    | CapabilitySource::ProductionObservation
            ),
            CapabilityStatus::Degraded => matches!(
                source,
                CapabilitySource::RuntimeHandshake
                    | CapabilitySource::ActiveProbe
                    | CapabilitySource::ProductionObservation
            ),
            CapabilityStatus::Broken | CapabilityStatus::Unsupported => matches!(
                source,
                CapabilitySource::ActiveProbe | CapabilitySource::ReproducedFailure
            ),
        };
        if source == CapabilitySource::ImportedLegacyDeclaration {
            return Err(EvidenceRelationError::LegacySourceNeverVerified);
        }
        if matches!(source, CapabilitySource::ReproducedFailure)
            && matches!(
                status,
                CapabilityStatus::ProbePassed | CapabilityStatus::Observed
            )
        {
            return Err(EvidenceRelationError::FailureSourceNeverPositive);
        }
        if !admissible {
            return Err(EvidenceRelationError::StatusSourceMismatch);
        }
        Ok(Self {
            skill_id: skill_id.into(),
            status,
            source,
            scope_fingerprint,
            limitations_and_negative_evidence: Vec::new(),
            evidence_refs: Vec::new(),
            requalification: None,
            observed_at,
            expires_at: None,
        })
    }

    /// Declares that this record requalifies the failure or dependency change
    /// published under `blocking_evidence_ref`.
    ///
    /// The reference must be one hex SHA-256 digest, so a requalification can
    /// only name a reference the owner actually published. The registry still
    /// requires the naming to match a retained [`InvalidationCause`] and the
    /// owner-issued revision to be strictly newer than the blocking revision;
    /// this builder records the causal claim, it does not grant the clear.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceRevisionError::MalformedRequalificationRef`] when the
    /// reference is not one hex SHA-256 digest.
    pub fn requalifying(
        mut self,
        blocking_evidence_ref: &str,
    ) -> Result<Self, EvidenceRevisionError> {
        if !is_evidence_ref(blocking_evidence_ref) {
            return Err(EvidenceRevisionError::MalformedRequalificationRef);
        }
        self.requalification = Some(blocking_evidence_ref.to_owned());
        Ok(self)
    }

    /// Attaches an expiry bound; the record stops admitting once `now`
    /// reaches `expires_at`.
    #[must_use]
    pub const fn expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Returns true when this record is time-fresh at `now`: observed
    /// no later than now, with no reached expiry.
    ///
    /// Exposed so the route registry reuses the same time predicate when it
    /// reports why a route was refused, instead of re-deriving freshness.
    #[must_use]
    pub fn is_time_fresh(&self, now: u64) -> bool {
        self.observed_at <= now && self.expires_at.is_none_or(|expires| now < expires)
    }

    /// Returns true when this record's own status and source could admit
    /// production work on any scope: `probe_passed` or `observed` from an
    /// admissible evidence source.
    ///
    /// This is the single definition of qualifying evidence, shared by
    /// [`is_fresh_positive_for`](Self::is_fresh_positive_for) and by
    /// [`CapabilityRegistry::insert`], so the status/source rule that admits
    /// a route and the status/source rule that requalifies a stale scope
    /// cannot drift apart.
    fn is_qualifying_evidence(&self) -> bool {
        matches!(
            self.status,
            CapabilityStatus::ProbePassed | CapabilityStatus::Observed
        ) && self.source.is_admissible_evidence()
    }

    /// Returns whether the status is a production restriction. This predicate
    /// intentionally ignores freshness: if capacity prevents retaining a
    /// negative record, the registry must fail closed.
    fn is_restrictive_evidence(&self) -> bool {
        matches!(
            self.status,
            CapabilityStatus::Degraded | CapabilityStatus::Broken | CapabilityStatus::Unsupported
        )
    }

    /// Returns true when this record is a fresh exact-fingerprint positive
    /// that may admit production work: `probe_passed` or `observed` from an
    /// admissible evidence source, time-fresh at `now`, on a scope the
    /// registry has not invalidated.
    #[must_use]
    pub fn is_fresh_positive_for(
        &self,
        skill_id: &str,
        scope: &RouteScopeFingerprint,
        now: u64,
        invalidated: &BTreeMap<RouteScopeFingerprint, InvalidationCause>,
    ) -> bool {
        self.skill_id == skill_id
            && self.scope_fingerprint.exact_match(scope)
            && !invalidated.contains_key(&self.scope_fingerprint)
            && self.is_time_fresh(now)
            && self.is_qualifying_evidence()
    }

    /// Returns true when this record restricts production work on an exact
    /// fingerprint: fresh `broken`, `unsupported`, or `degraded` evidence.
    /// Degraded evidence restricts exactly like a negative: a degraded
    /// route is not a production route until it re-qualifies.
    #[must_use]
    pub fn is_fresh_restriction_for(
        &self,
        skill_id: &str,
        scope: &RouteScopeFingerprint,
        now: u64,
        invalidated: &BTreeMap<RouteScopeFingerprint, InvalidationCause>,
    ) -> bool {
        self.skill_id == skill_id
            && self.scope_fingerprint.exact_match(scope)
            && !invalidated.contains_key(&self.scope_fingerprint)
            && match self.status {
                CapabilityStatus::Broken | CapabilityStatus::Unsupported => self.observed_at <= now,
                CapabilityStatus::Degraded => self.is_time_fresh(now),
                _ => return false,
            }
    }
}

impl From<&ImportedLegacyEvidence> for CapabilityEvidenceRecord {
    /// Normalizes a legacy import into the canonical registry shape.
    /// The `declared` / `imported_legacy_declaration` semantics are preserved
    /// exactly; unknown scope fields stay unknown.
    fn from(imported: &ImportedLegacyEvidence) -> Self {
        Self {
            skill_id: imported.skill_id.clone(),
            status: CapabilityStatus::Declared,
            source: CapabilitySource::ImportedLegacyDeclaration,
            scope_fingerprint: RouteScopeFingerprint {
                // A legacy declaration carries none of the complete effective
                // route identity beyond the six dimensions the import shape
                // declares; every further behaviour-changing group stays
                // `None` (unknown), never back-filled from the route the
                // declaration names.
                host_family: None,
                adapter_id: None,
                protocol_transport: None,
                runtime_hash: imported.scope.runtime_hash.clone(),
                adapter_hash: imported.scope.adapter_hash.clone(),
                os_architecture: imported.scope.os_architecture.clone(),
                auth_profile_class: imported.scope.auth_profile_class.clone(),
                provider_model_route: imported.scope.provider_model_route.clone(),
                tool_call_id_and_role_ordering: None,
                reasoning_continuation_and_compaction: None,
                feature_flags_and_serializer: imported.scope.feature_flags_and_serializer.clone(),
            },
            limitations_and_negative_evidence: Vec::new(),
            evidence_refs: Vec::new(),
            requalification: None,
            observed_at: 0,
            expires_at: None,
        }
    }
}

/// Standing of one skill in the retained registry at an observation time.
///
/// Aggregation of the verified admission predicates across the skill's
/// retained scopes: a fresh restriction on any retained scope restricts the
/// skill (mirroring [`CapabilityRegistry::admit_production_route` denying on
/// any fresh restriction); otherwise a fresh positive on any retained scope
/// holds it; anything else (declared-only, stale, expired, future-dated, or
/// invalidated evidence, or no records at all) leaves it unevaluated. No new
/// semantics: this names the per-skill outcome of the existing predicates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillStanding {
    /// At least one fresh exact-scope positive with no fresh restriction.
    Holding,
    /// At least one fresh exact-scope restriction (broken, unsupported, or
    /// degraded evidence).
    Restricted,
    /// No fresh positive and no fresh restriction.
    Unevaluated,
}

/// Governor-owned canonical registry of scoped capability evidence.
#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    /// One retained record per `(skill_id, scope_fingerprint)` key, each with
    /// the owner-issued revision that orders its key.
    records: Vec<RetainedCapabilityEvidence>,
    /// Derived staleness: scope fingerprints invalidated by an applied
    /// scope change, each retained with the owner-issued reference and
    /// revision of the blocking failure or change. A retained record is
    /// replaced only by strictly newer owner-issued evidence for the same key,
    /// and an entry is cleared only by a qualifying record that names the
    /// retained blocking reference and is strictly newer than it. Freshness
    /// additionally runs from this map plus `observed_at`/`expires_at` at
    /// admission time.
    invalidated_scopes: BTreeMap<RouteScopeFingerprint, InvalidationCause>,
    /// Set only when a new restriction could not be retained because the
    /// registry reached its record bound. Since that missing restriction's
    /// scope cannot be represented without growing state, the registry
    /// refuses all production admission for this instance's lifetime.
    restriction_capacity_exhausted: bool,
}

impl CapabilityRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            invalidated_scopes: BTreeMap::new(),
            restriction_capacity_exhausted: false,
        }
    }

    /// Inserts one evidence record for its `(skill_id, scope_fingerprint)`
    /// key under the owner-issued revision the canonical store issued for it,
    /// superseding the record already retained for that key.
    ///
    /// Supersession is decided by the immutable owner-issued revision, never by
    /// arrival order and never by a locally observed instant. A record whose
    /// [`OwnerEvidenceRevision::owner_revision`] is not strictly newer than the
    /// retained revision for the same key is a delayed replay and is refused
    /// whole: it displaces nothing and clears no invalidation, so a delayed old
    /// `probe_passed` can neither replace a newer `broken` record nor revive
    /// the scope that record restricted. An identical replay of the retained
    /// owner revision converges instead of superseding, matching the immutable
    /// row identity the store arbitrates.
    ///
    /// `observed_at` deliberately carries no ordering authority here. It is
    /// record content: the evidence source stamps it, so a delayed writer
    /// chooses its own value and a locally compared instant is not owner
    /// authority. Freshness still runs at admission time against the caller's
    /// `now` through [`CapabilityEvidenceRecord::is_time_fresh`].
    ///
    /// A scope-wide invalidation is cleared only by a fresh requalification
    /// that names the retained blocking reference exactly and carries a
    /// strictly newer owner-issued revision — see
    /// [`CapabilityEvidenceRecord::requalifying`]. Qualifying evidence that
    /// names no blocking reference, or names a different one, is still retained
    /// as the key's current record but leaves the invalidation standing. An
    /// insertion that opens a new key never revives a scope another capability's
    /// evidence invalidated, so a scope-wide invalidation is not cleared by an
    /// unrelated capability insertion on the same fingerprint.
    ///
    /// A same-key replacement remains possible at capacity. A new key is
    /// refused once the bound is reached, preserving every retained
    /// supersession frontier. If the refused record is restrictive, the
    /// registry enters a bounded fail-closed admission state because it cannot
    /// retain the scope of that missing restriction.
    ///
    /// Returns `true` when the record was inserted or replaced, and `false`
    /// when it was an equal/older replay or a new key exceeded capacity.
    pub fn insert(
        &mut self,
        record: CapabilityEvidenceRecord,
        revision: OwnerEvidenceRevision,
    ) -> bool {
        if let Some(retained) = self.records.iter().position(|existing| {
            existing.record.skill_id == record.skill_id
                && existing.record.scope_fingerprint == record.scope_fingerprint
        }) {
            if revision.owner_revision <= self.records[retained].revision.owner_revision {
                return false;
            }
            self.clear_invalidation_by_requalification(&record, &revision);
            self.records[retained] = RetainedCapabilityEvidence { record, revision };
            return true;
        }
        if self.records.len() >= MAX_CAPABILITY_EVIDENCE_RECORDS {
            self.restriction_capacity_exhausted |= record.is_restrictive_evidence();
            return false;
        }
        self.records
            .push(RetainedCapabilityEvidence { record, revision });
        true
    }

    /// Clears the scope invalidation only when this record is a qualifying
    /// requalification of exactly the retained blocking cause.
    fn clear_invalidation_by_requalification(
        &mut self,
        record: &CapabilityEvidenceRecord,
        revision: &OwnerEvidenceRevision,
    ) {
        if !record.is_qualifying_evidence() {
            return;
        }
        let Some(cause) = self
            .invalidated_scopes
            .get(&record.scope_fingerprint)
            .cloned()
        else {
            return;
        };
        let names_blocking_reference = record
            .requalification
            .as_deref()
            .is_some_and(|named| named == cause.blocking_evidence_ref);
        if !names_blocking_reference
            || revision.owner_revision <= cause.blocking_revision.owner_revision
        {
            return;
        }
        self.invalidated_scopes.remove(&record.scope_fingerprint);
    }

    /// Returns every retained record with its owner-issued revision, including
    /// invalidated and declared-only entries.
    #[must_use]
    pub fn retained(&self) -> &[RetainedCapabilityEvidence] {
        &self.records
    }

    /// Returns the owner-issued revision retained for one
    /// `(skill_id, scope_fingerprint)` key, when it is retained.
    #[must_use]
    pub fn retained_revision(
        &self,
        skill_id: &str,
        scope: &RouteScopeFingerprint,
    ) -> Option<&OwnerEvidenceRevision> {
        self.records
            .iter()
            .find(|retained| {
                retained.record.skill_id == skill_id
                    && retained.record.scope_fingerprint.exact_match(scope)
            })
            .map(|retained| &retained.revision)
    }

    /// Returns the number of retained records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns the canonical required capability set: distinct skill
    /// identities with retained evidence records, sorted.
    ///
    /// This is the daemon's observed capability model: the installation
    /// capabilities with any retained evidence (positive, restrictive, or
    /// declared). Empty means cold: no model retained yet, never an
    /// evaluated empty requirement.
    #[must_use]
    pub fn required_set(&self) -> Vec<String> {
        self.records
            .iter()
            .map(|retained| retained.record.skill_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Returns the standing of one skill at `now` across its retained scopes.
    #[must_use]
    pub fn skill_standing(&self, skill_id: &str, now: u64) -> SkillStanding {
        let mut positive = false;
        for retained in &self.records {
            let record = &retained.record;
            if record.skill_id != skill_id {
                continue;
            }
            if record.is_fresh_restriction_for(
                skill_id,
                &record.scope_fingerprint,
                now,
                &self.invalidated_scopes,
            ) {
                return SkillStanding::Restricted;
            }
            if record.is_fresh_positive_for(
                skill_id,
                &record.scope_fingerprint,
                now,
                &self.invalidated_scopes,
            ) {
                positive = true;
            }
        }
        if positive {
            if self.restriction_capacity_exhausted {
                SkillStanding::Unevaluated
            } else {
                SkillStanding::Holding
            }
        } else {
            SkillStanding::Unevaluated
        }
    }

    /// Returns true when no records are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns true when this scope fingerprint was invalidated by an
    /// applied scope change and not since re-qualified by a record naming the
    /// retained blocking reference.
    #[must_use]
    pub fn is_scope_invalidated(&self, scope: &RouteScopeFingerprint) -> bool {
        self.invalidated_scopes.contains_key(scope)
    }

    /// Returns the retained invalidation cause for one scope, when it is
    /// currently invalidated.
    #[must_use]
    pub fn invalidation_cause(&self, scope: &RouteScopeFingerprint) -> Option<&InvalidationCause> {
        self.invalidated_scopes.get(scope)
    }

    /// Returns every currently invalidated scope with its retained cause.
    #[must_use]
    pub fn invalidated_scopes(&self) -> &BTreeMap<RouteScopeFingerprint, InvalidationCause> {
        &self.invalidated_scopes
    }

    /// Production admission for one skill on one exact route scope at `now`.
    ///
    /// Requires at least one fresh exact-fingerprint `probe_passed` or
    /// `observed` record from an admissible evidence source, and no fresh
    /// exact-fingerprint `broken`, `unsupported`, or `degraded` record.
    /// Declared/imported records alone never admit.
    #[must_use]
    pub fn admit_production_route(
        &self,
        skill_id: &str,
        scope: &RouteScopeFingerprint,
        now: u64,
    ) -> bool {
        if self.restriction_capacity_exhausted {
            return false;
        }
        if self.records.iter().any(|retained| {
            retained
                .record
                .is_fresh_restriction_for(skill_id, scope, now, &self.invalidated_scopes)
        }) {
            return false;
        }
        self.records.iter().any(|retained| {
            retained
                .record
                .is_fresh_positive_for(skill_id, scope, now, &self.invalidated_scopes)
        })
    }

    /// Stales the evidence depending on the changed dimensions, recording the
    /// owner-issued cause every newly invalidated scope must be requalified
    /// against.
    ///
    /// Only records differing from `current` on at least one selected
    /// dependency dimension join the invalidation set; unrelated
    /// routes/accounts whose selected fields still match stay admitted. A
    /// runtime, adapter, provider, serializer, or behavior-affecting profile
    /// change therefore invalidates dependent positive evidence instead of
    /// leaving it authorizing production work.
    ///
    /// `blocking_evidence_ref` is the exact owner-issued reference of the
    /// applied change — the digest of the observed behaviour scope
    /// ([`RouteScopeFingerprint::reference_digest`]). It is retained per
    /// invalidated scope, so the invalidation can only be cleared by a record
    /// that names this exact reference and carries a strictly newer
    /// owner-issued revision ([`CapabilityEvidenceRecord::requalifying`]). An
    /// already-invalidated scope keeps its original cause, so the earliest
    /// published change remains the reference a requalification has to answer.
    ///
    /// The blocking revision is the highest owner-issued revision among the
    /// records this change actually staled, read from the revisions the
    /// canonical store issued. It is never synthesized from a local clock, so
    /// the "strictly newer than the evidence it invalidated" rule is measured
    /// entirely in owner authority.
    ///
    /// Returns the count of newly staled records.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceRevisionError::MalformedEvidenceRef`] when
    /// `blocking_evidence_ref` is not one hex SHA-256 digest; nothing is
    /// staled in that case, so a malformed change reference cannot invalidate
    /// a scope.
    pub fn apply_scope_change(
        &mut self,
        current: &RouteScopeFingerprint,
        changed: ScopeDependencySelector,
        blocking_evidence_ref: &str,
    ) -> Result<usize, EvidenceRevisionError> {
        if !is_evidence_ref(blocking_evidence_ref) {
            return Err(EvidenceRevisionError::MalformedEvidenceRef);
        }
        let mut newly_staled = 0;
        for retained in &self.records {
            let scope = &retained.record.scope_fingerprint;
            if self.invalidated_scopes.contains_key(scope)
                || !changed.selects_difference(scope, current)
            {
                continue;
            }
            // The blocking revision is the newest owner-issued revision this
            // change invalidated, so a requalification must be strictly newer
            // than the evidence it replaced.
            let blocking_revision = match self.invalidated_scopes.get(scope) {
                Some(cause) => cause.blocking_revision.clone(),
                None => self
                    .records
                    .iter()
                    .filter(|other| other.record.scope_fingerprint.exact_match(scope))
                    .map(|other| other.revision.clone())
                    .max()
                    .unwrap_or_else(OwnerEvidenceRevision::legacy_declared),
            };
            self.invalidated_scopes.insert(
                scope.clone(),
                InvalidationCause::new(blocking_evidence_ref, blocking_revision)?,
            );
            newly_staled += 1;
        }
        Ok(newly_staled)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_config::legacy_capability_import::{
        LegacyCapabilityDeclaration, LegacyScopeFingerprint, import_legacy_declaration,
    };

    fn scope() -> RouteScopeFingerprint {
        RouteScopeFingerprint {
            host_family: Some("host-family-1".into()),
            adapter_id: Some("adapter-id-1".into()),
            protocol_transport: Some("app-server|stdio".into()),
            runtime_hash: Some("runtime-hash-1".into()),
            adapter_hash: Some("adapter-hash-1".into()),
            os_architecture: Some("x86_64-windows".into()),
            auth_profile_class: Some("user-broker".into()),
            provider_model_route: Some("provider/model/auth".into()),
            tool_call_id_and_role_ordering: Some("tool-call-id-1".into()),
            reasoning_continuation_and_compaction: Some("reasoning-compaction-1".into()),
            feature_flags_and_serializer: Some("serializer-v1".into()),
        }
    }

    fn probe(
        skill: &str,
        scope: RouteScopeFingerprint,
        observed_at: u64,
    ) -> CapabilityEvidenceRecord {
        CapabilityEvidenceRecord::verified(
            skill,
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            scope,
            observed_at,
        )
        .expect("valid probe evidence verifies")
    }

    /// Deterministic stand-in for a store-issued evidence revision.
    fn rev(owner_revision: u64) -> OwnerEvidenceRevision {
        OwnerEvidenceRevision::issued(
            owner_revision,
            &eliot_store_api::sha256_hex(&owner_revision.to_be_bytes()),
        )
        .expect("fixture revision is well formed")
    }

    /// Deterministic stand-in for the owner-issued reference of an applied
    /// dependency change.
    fn change_ref() -> String {
        eliot_store_api::sha256_hex(b"fixture.applied-scope-change")
    }

    #[test]
    fn capability_evidence_acceptance_1957() {
        // Legacy declaration appears only as declared/imported_legacy and
        // cannot admit a production route.
        let imported = import_legacy_declaration(&LegacyCapabilityDeclaration {
            skill_id: "route.execute".into(),
            scope: LegacyScopeFingerprint {
                runtime_hash: Some("runtime-hash-1".into()),
                adapter_hash: Some("adapter-hash-1".into()),
                os_architecture: Some("x86_64-windows".into()),
                auth_profile_class: Some("user-broker".into()),
                provider_model_route: Some("provider/model/auth".into()),
                feature_flags_and_serializer: Some("serializer-v1".into()),
            },
        })
        .expect("legacy declaration imports");
        let legacy_record = CapabilityEvidenceRecord::from(&imported);
        assert_eq!(legacy_record.status, CapabilityStatus::Declared);
        assert_eq!(
            legacy_record.source,
            CapabilitySource::ImportedLegacyDeclaration
        );
        let mut registry = CapabilityRegistry::new();
        registry.insert(legacy_record, OwnerEvidenceRevision::legacy_declared());
        assert!(!registry.admit_production_route("route.execute", &scope(), 10));

        // A fresh exact-fingerprint probe_passed record admits the same route.
        registry.insert(probe("route.execute", scope(), 1), rev(1));
        assert!(registry.admit_production_route("route.execute", &scope(), 10));

        // An exact-fingerprint broken record subsequently restricts it; the
        // superseding broken record replaces nothing else.
        registry.insert(
            CapabilityEvidenceRecord::verified(
                "route.execute",
                CapabilityStatus::Broken,
                CapabilitySource::ReproducedFailure,
                scope(),
                2,
            )
            .expect("valid failure evidence verifies"),
            rev(2),
        );
        assert!(!registry.admit_production_route("route.execute", &scope(), 10));

        // Adapter-hash or serializer change stales the earlier positive
        // evidence: a registry holding only legacy + positive evidence no
        // longer admits after the dependency change.
        let mut rotated = CapabilityRegistry::new();
        rotated.insert(
            CapabilityEvidenceRecord::from(&imported),
            OwnerEvidenceRevision::legacy_declared(),
        );
        rotated.insert(probe("route.execute", scope(), 1), rev(1));
        assert!(rotated.admit_production_route("route.execute", &scope(), 10));
        let mut changed = scope();
        changed.adapter_hash = Some("adapter-hash-2".into());
        let adapter_only = ScopeDependencySelector {
            adapter_hash: true,
            ..ScopeDependencySelector::none()
        };
        assert!(
            rotated
                .apply_scope_change(&changed, adapter_only, &change_ref())
                .unwrap()
                >= 1
        );
        assert!(!rotated.admit_production_route("route.execute", &changed, 10));
        let mut changed_serializer = scope();
        changed_serializer.feature_flags_and_serializer = Some("serializer-v2".into());
        let mut rotated_serializer = CapabilityRegistry::new();
        rotated_serializer.insert(probe("route.execute", scope(), 1), rev(1));
        assert!(rotated_serializer.admit_production_route("route.execute", &scope(), 10));
        let serializer_only = ScopeDependencySelector {
            feature_flags_and_serializer: true,
            ..ScopeDependencySelector::none()
        };
        assert!(
            rotated_serializer
                .apply_scope_change(&changed_serializer, serializer_only, &change_ref())
                .unwrap()
                >= 1
        );
        assert!(!rotated_serializer.admit_production_route(
            "route.execute",
            &changed_serializer,
            10
        ));
    }

    #[test]
    fn admissibility_is_a_property_of_the_source() {
        // probe_passed from the official contract admits; the same status
        // from a legacy import or a failure report never admits.
        let official = CapabilityEvidenceRecord::verified(
            "skill-a",
            CapabilityStatus::ProbePassed,
            CapabilitySource::OfficialContract,
            scope(),
            1,
        )
        .expect("contract evidence verifies");
        assert!(official.source.is_admissible_evidence());
        let mut registry = CapabilityRegistry::new();
        registry.insert(official, rev(1));
        assert!(registry.admit_production_route("skill-a", &scope(), 10));

        assert!(!CapabilitySource::ImportedLegacyDeclaration.is_admissible_evidence());
        assert!(!CapabilitySource::ReproducedFailure.is_admissible_evidence());
        assert_eq!(
            CapabilityEvidenceRecord::verified(
                "skill-a",
                CapabilityStatus::ProbePassed,
                CapabilitySource::ImportedLegacyDeclaration,
                scope(),
                1,
            ),
            Err(EvidenceRelationError::LegacySourceNeverVerified)
        );
        assert_eq!(
            CapabilityEvidenceRecord::verified(
                "skill-a",
                CapabilityStatus::ProbePassed,
                CapabilitySource::ReproducedFailure,
                scope(),
                1,
            ),
            Err(EvidenceRelationError::FailureSourceNeverPositive)
        );
    }

    #[test]
    fn verified_rejects_unverifiable_relations() {
        assert_eq!(
            CapabilityEvidenceRecord::verified(
                "skill-a",
                CapabilityStatus::Declared,
                CapabilitySource::ActiveProbe,
                scope(),
                1,
            ),
            Err(EvidenceRelationError::DeclaredIsLegacyOnly)
        );
        assert_eq!(
            CapabilityEvidenceRecord::verified(
                "skill-a",
                CapabilityStatus::Unknown,
                CapabilitySource::ActiveProbe,
                scope(),
                1,
            ),
            Err(EvidenceRelationError::UnknownIsNeverVerified)
        );
        assert_eq!(
            CapabilityEvidenceRecord::verified(
                "skill-a",
                CapabilityStatus::Observed,
                CapabilitySource::ActiveProbe,
                scope(),
                1,
            ),
            Err(EvidenceRelationError::StatusSourceMismatch)
        );
        assert_eq!(
            CapabilityEvidenceRecord::verified(
                "  ",
                CapabilityStatus::ProbePassed,
                CapabilitySource::ActiveProbe,
                scope(),
                1,
            ),
            Err(EvidenceRelationError::StatusSourceMismatch)
        );
    }

    #[test]
    fn positive_evidence_expires_at_the_observation_time() {
        let mut registry = CapabilityRegistry::new();
        registry.insert(probe("skill-a", scope(), 1).expires_at(10), rev(1));
        assert!(registry.admit_production_route("skill-a", &scope(), 9));
        assert!(!registry.admit_production_route("skill-a", &scope(), 10));
        assert!(!registry.admit_production_route("skill-a", &scope(), 11));
    }

    #[test]
    fn future_observations_do_not_admit() {
        let mut registry = CapabilityRegistry::new();
        registry.insert(probe("skill-a", scope(), 20), rev(1));
        assert!(!registry.admit_production_route("skill-a", &scope(), 10));
        assert!(registry.admit_production_route("skill-a", &scope(), 20));
    }

    #[test]
    fn degraded_evidence_restricts_the_exact_scope() {
        let mut registry = CapabilityRegistry::new();
        registry.insert(probe("skill-a", scope(), 1), rev(1));
        assert!(registry.admit_production_route("skill-a", &scope(), 10));
        registry.insert(
            CapabilityEvidenceRecord::verified(
                "skill-a",
                CapabilityStatus::Degraded,
                CapabilitySource::ProductionObservation,
                scope(),
                2,
            )
            .expect("valid degradation verifies"),
            rev(2),
        );
        // The superseding degraded record replaces the positive: the route
        // is restricted until fresh positive evidence re-qualifies it.
        assert!(!registry.admit_production_route("skill-a", &scope(), 10));
        registry.insert(probe("skill-a", scope(), 3), rev(3));
        assert!(registry.admit_production_route("skill-a", &scope(), 10));
    }

    #[test]
    fn scope_change_is_narrowed_by_dependency_selector() {
        let mut registry = CapabilityRegistry::new();
        registry.insert(probe("skill-a", scope(), 1), rev(1));
        let mut other = scope();
        other.provider_model_route = Some("other/model/auth".into());
        registry.insert(probe("skill-b", other.clone(), 1), rev(1));
        let mut changed = scope();
        changed.adapter_hash = Some("adapter-hash-2".into());
        let adapter_only = ScopeDependencySelector {
            adapter_hash: true,
            ..ScopeDependencySelector::none()
        };
        // skill-b shares the stale adapter hash, so it stales; a selector
        // naming only the provider route would leave both untouched.
        assert_eq!(
            registry
                .apply_scope_change(&changed, adapter_only, &change_ref())
                .unwrap(),
            2
        );
        assert!(registry.is_scope_invalidated(&scope()));
        assert!(registry.is_scope_invalidated(&other));
        let fresh = CapabilityRegistry::new();
        let mut fresh_registry = fresh;
        fresh_registry.insert(probe("skill-a", scope(), 1), rev(1));
        let provider_only = ScopeDependencySelector {
            provider_model_route: true,
            ..ScopeDependencySelector::none()
        };
        assert_eq!(
            fresh_registry
                .apply_scope_change(&changed, provider_only, &change_ref())
                .unwrap(),
            0
        );
        assert!(fresh_registry.admit_production_route("skill-a", &scope(), 10));
    }

    #[test]
    fn insert_supersedes_and_evicts_oldest_first() {
        let mut registry = CapabilityRegistry::new();
        registry.insert(probe("skill-a", scope(), 1), rev(1));
        registry.insert(probe("skill-a", scope(), 2), rev(2));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.retained()[0].record.observed_at, 2);
        for index in 0..MAX_CAPABILITY_EVIDENCE_RECORDS {
            let mut scoped = scope();
            scoped.runtime_hash = Some(format!("runtime-hash-{index}"));
            registry.insert(probe(&format!("skill-{index}"), scoped, 1), rev(1));
        }
        assert_eq!(registry.len(), MAX_CAPABILITY_EVIDENCE_RECORDS);
        // The superseded skill-a record (oldest fingerprint order) evicted;
        // the newest insert is retained.
        assert!(
            !registry
                .retained()
                .iter()
                .any(|retained| retained.record.skill_id == "skill-a")
        );
    }

    #[test]
    fn fresh_evidence_requalifies_an_invalidated_scope() {
        let mut registry = CapabilityRegistry::new();
        registry.insert(probe("skill-a", scope(), 1), rev(1));
        let mut changed = scope();
        changed.adapter_hash = Some("adapter-hash-2".into());
        assert!(
            registry
                .apply_scope_change(&changed, ScopeDependencySelector::all(), &change_ref())
                .unwrap()
                >= 1
        );
        assert!(!registry.admit_production_route("skill-a", &scope(), 10));
        registry.insert(probe("skill-a", scope(), 3), rev(3));
        assert!(!registry.is_scope_invalidated(&scope()));
        assert!(registry.admit_production_route("skill-a", &scope(), 10));
    }

    #[test]
    fn required_set_is_the_sorted_retained_skill_model() {
        let mut registry = CapabilityRegistry::new();
        assert!(registry.required_set().is_empty());
        registry.insert(probe("skill-b", scope(), 1), rev(1));
        let mut other = scope();
        other.adapter_hash = Some("adapter-hash-2".into());
        registry.insert(probe("skill-a", other, 1), rev(1));
        // Superseding insert on the same skill/scope keeps one entry.
        registry.insert(probe("skill-b", scope(), 2), rev(2));
        assert_eq!(registry.required_set(), vec!["skill-a", "skill-b"]);
    }

    #[test]
    fn skill_standing_aggregates_verified_predicates() {
        let mut registry = CapabilityRegistry::new();
        assert_eq!(
            registry.skill_standing("skill-a", 10),
            SkillStanding::Unevaluated
        );
        registry.insert(probe("skill-a", scope(), 1), rev(1));
        assert_eq!(
            registry.skill_standing("skill-a", 10),
            SkillStanding::Holding
        );
        // Future-dated observation is not fresh.
        assert_eq!(
            registry.skill_standing("skill-a", 0),
            SkillStanding::Unevaluated
        );
        // A fresh restriction on the same skill overrides the positive.
        registry.insert(
            CapabilityEvidenceRecord::verified(
                "skill-a",
                CapabilityStatus::Broken,
                CapabilitySource::ReproducedFailure,
                scope(),
                2,
            )
            .expect("valid failure evidence verifies"),
            rev(2),
        );
        assert_eq!(
            registry.skill_standing("skill-a", 10),
            SkillStanding::Restricted
        );
        // Other skills are unaffected.
        assert_eq!(
            registry.skill_standing("skill-b", 10),
            SkillStanding::Unevaluated
        );
    }

    #[test]
    fn skill_standing_without_fresh_evidence_is_unevaluated() {
        let mut registry = CapabilityRegistry::new();
        // Declared-only legacy evidence never holds nor restricts.
        let imported = import_legacy_declaration(&LegacyCapabilityDeclaration {
            skill_id: "skill-a".into(),
            scope: LegacyScopeFingerprint::default(),
        })
        .expect("legacy declaration imports");
        registry.insert(
            CapabilityEvidenceRecord::from(&imported),
            OwnerEvidenceRevision::legacy_declared(),
        );
        assert_eq!(
            registry.skill_standing("skill-a", 10),
            SkillStanding::Unevaluated
        );
        // Expired positive evidence is stale, not holding.
        registry.insert(probe("skill-a", scope(), 1).expires_at(10), rev(1));
        assert_eq!(
            registry.skill_standing("skill-a", 10),
            SkillStanding::Unevaluated
        );
        // An invalidated scope no longer holds until requalified.
        let mut holding = CapabilityRegistry::new();
        holding.insert(probe("skill-a", scope(), 1), rev(1));
        let mut changed = scope();
        changed.adapter_hash = Some("adapter-hash-2".into());
        assert!(
            holding
                .apply_scope_change(&changed, ScopeDependencySelector::all(), &change_ref())
                .unwrap()
                >= 1
        );
        assert_eq!(
            holding.skill_standing("skill-a", 10),
            SkillStanding::Unevaluated
        );
    }
}
