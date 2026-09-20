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

#![forbid(unsafe_code)]

use std::collections::HashSet;

use eliot_config::legacy_capability_import::ImportedLegacyEvidence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum retained evidence records. Insertion beyond the bound evicts the
/// oldest record first, so the registry cannot grow without bound while a
/// re-probe keeps the newest evidence for its key.
pub const MAX_CAPABILITY_EVIDENCE_RECORDS: usize = 512;

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
/// Fields the source cannot provide stay `None` (unknown, never inferred).
/// `None` matches only `None` during exact-fingerprint comparison.
#[derive(Clone, Debug, Default, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteScopeFingerprint {
    pub runtime_hash: Option<String>,
    pub adapter_hash: Option<String>,
    pub os_architecture: Option<String>,
    pub auth_profile_class: Option<String>,
    pub provider_model_route: Option<String>,
    pub feature_flags_and_serializer: Option<String>,
}

impl RouteScopeFingerprint {
    /// Returns true when every fingerprint field is exactly equal.
    #[must_use]
    pub fn exact_match(&self, other: &Self) -> bool {
        self == other
    }
}

/// Narrows a scope change to the dependency dimensions that actually moved.
///
/// A runtime, adapter, provider, serializer, or behavior-affecting profile
/// change stales only the evidence depending on a selected dimension; routes
/// and accounts whose selected fields still match the current fingerprint
/// stay admitted. [`ScopeDependencySelector::all`] reproduces the coarse
/// whole-fingerprint invalidation for callers that cannot attribute the
/// change more narrowly. Six independent dependency dimensions stay six
/// explicit flags (not a bitmask) so each contract dimension reads by name.
#[allow(
    clippy::struct_excessive_bools,
    reason = "six named I03-04 dependency dimensions"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeDependencySelector {
    pub runtime_hash: bool,
    pub adapter_hash: bool,
    pub os_architecture: bool,
    pub auth_profile_class: bool,
    pub provider_model_route: bool,
    pub feature_flags_and_serializer: bool,
}

impl ScopeDependencySelector {
    /// Selects every dependency dimension (coarse whole-scope invalidation).
    #[must_use]
    pub const fn all() -> Self {
        Self {
            runtime_hash: true,
            adapter_hash: true,
            os_architecture: true,
            auth_profile_class: true,
            provider_model_route: true,
            feature_flags_and_serializer: true,
        }
    }

    /// Selects no dimension; application stales nothing.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            runtime_hash: false,
            adapter_hash: false,
            os_architecture: false,
            auth_profile_class: false,
            provider_model_route: false,
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
        (self.runtime_hash && record.runtime_hash != current.runtime_hash)
            || (self.adapter_hash && record.adapter_hash != current.adapter_hash)
            || (self.os_architecture && record.os_architecture != current.os_architecture)
            || (self.auth_profile_class && record.auth_profile_class != current.auth_profile_class)
            || (self.provider_model_route
                && record.provider_model_route != current.provider_model_route)
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
            observed_at,
            expires_at: None,
        })
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
    fn is_time_fresh(&self, now: u64) -> bool {
        self.observed_at <= now && self.expires_at.is_none_or(|expires| now < expires)
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
        invalidated: &HashSet<RouteScopeFingerprint>,
    ) -> bool {
        self.skill_id == skill_id
            && self.scope_fingerprint.exact_match(scope)
            && !invalidated.contains(&self.scope_fingerprint)
            && self.is_time_fresh(now)
            && matches!(
                self.status,
                CapabilityStatus::ProbePassed | CapabilityStatus::Observed
            )
            && self.source.is_admissible_evidence()
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
        invalidated: &HashSet<RouteScopeFingerprint>,
    ) -> bool {
        self.skill_id == skill_id
            && self.scope_fingerprint.exact_match(scope)
            && !invalidated.contains(&self.scope_fingerprint)
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
                runtime_hash: imported.scope.runtime_hash.clone(),
                adapter_hash: imported.scope.adapter_hash.clone(),
                os_architecture: imported.scope.os_architecture.clone(),
                auth_profile_class: imported.scope.auth_profile_class.clone(),
                provider_model_route: imported.scope.provider_model_route.clone(),
                feature_flags_and_serializer: imported.scope.feature_flags_and_serializer.clone(),
            },
            limitations_and_negative_evidence: Vec::new(),
            evidence_refs: Vec::new(),
            observed_at: 0,
            expires_at: None,
        }
    }
}

/// Governor-owned canonical registry of scoped capability evidence.
#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    records: Vec<CapabilityEvidenceRecord>,
    /// Derived staleness: scope fingerprints invalidated by an applied
    /// scope change. Records are never mutated in place; freshness is
    /// derived from this set plus `observed_at`/`expires_at` at admission
    /// time.
    invalidated_scopes: HashSet<RouteScopeFingerprint>,
}

impl CapabilityRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            invalidated_scopes: HashSet::new(),
        }
    }

    /// Inserts one evidence record, superseding any earlier record for the
    /// same skill and scope fingerprint.
    ///
    /// Re-probing the same skill/scope replaces the earlier record instead
    /// of appending: a later `broken` supersedes the earlier `probe_passed`
    /// (and a later passing re-probe supersedes the `broken`, re-qualifying
    /// the scope). Insertion beyond [`MAX_CAPABILITY_EVIDENCE_RECORDS`]
    /// evicts the oldest record first. A fresh record for an invalidated
    /// scope re-qualifies that scope.
    pub fn insert(&mut self, record: CapabilityEvidenceRecord) {
        self.records.retain(|existing| {
            existing.skill_id != record.skill_id
                || existing.scope_fingerprint != record.scope_fingerprint
        });
        self.invalidated_scopes.remove(&record.scope_fingerprint);
        self.records.push(record);
        while self.records.len() > MAX_CAPABILITY_EVIDENCE_RECORDS {
            self.records.remove(0);
        }
    }

    /// Returns all records, including invalidated and declared-only entries.
    #[must_use]
    pub fn records(&self) -> &[CapabilityEvidenceRecord] {
        &self.records
    }

    /// Returns the number of retained records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns true when no records are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns true when this scope fingerprint was invalidated by an
    /// applied scope change and not since re-qualified.
    #[must_use]
    pub fn is_scope_invalidated(&self, scope: &RouteScopeFingerprint) -> bool {
        self.invalidated_scopes.contains(scope)
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
        if self.records.iter().any(|record| {
            record.is_fresh_restriction_for(skill_id, scope, now, &self.invalidated_scopes)
        }) {
            return false;
        }
        self.records.iter().any(|record| {
            record.is_fresh_positive_for(skill_id, scope, now, &self.invalidated_scopes)
        })
    }

    /// Stales the evidence depending on the changed dimensions.
    ///
    /// Only records differing from `current` on at least one selected
    /// dependency dimension join the invalidation set; unrelated
    /// routes/accounts whose selected fields still match stay admitted. A
    /// runtime, adapter, provider, serializer, or behavior-affecting profile
    /// change therefore invalidates dependent positive evidence instead of
    /// leaving it authorizing production work. Returns the count of newly
    /// staled records.
    pub fn apply_scope_change(
        &mut self,
        current: &RouteScopeFingerprint,
        changed: ScopeDependencySelector,
    ) -> usize {
        let mut newly_staled = 0;
        for record in &self.records {
            if !self.invalidated_scopes.contains(&record.scope_fingerprint)
                && changed.selects_difference(&record.scope_fingerprint, current)
            {
                self.invalidated_scopes
                    .insert(record.scope_fingerprint.clone());
                newly_staled += 1;
            }
        }
        newly_staled
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
            runtime_hash: Some("runtime-hash-1".into()),
            adapter_hash: Some("adapter-hash-1".into()),
            os_architecture: Some("x86_64-windows".into()),
            auth_profile_class: Some("user-broker".into()),
            provider_model_route: Some("provider/model/auth".into()),
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
        registry.insert(legacy_record);
        assert!(!registry.admit_production_route("route.execute", &scope(), 10));

        // A fresh exact-fingerprint probe_passed record admits the same route.
        registry.insert(probe("route.execute", scope(), 1));
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
        );
        assert!(!registry.admit_production_route("route.execute", &scope(), 10));

        // Adapter-hash or serializer change stales the earlier positive
        // evidence: a registry holding only legacy + positive evidence no
        // longer admits after the dependency change.
        let mut rotated = CapabilityRegistry::new();
        rotated.insert(CapabilityEvidenceRecord::from(&imported));
        rotated.insert(probe("route.execute", scope(), 1));
        assert!(rotated.admit_production_route("route.execute", &scope(), 10));
        let mut changed = scope();
        changed.adapter_hash = Some("adapter-hash-2".into());
        let adapter_only = ScopeDependencySelector {
            adapter_hash: true,
            ..ScopeDependencySelector::none()
        };
        assert!(rotated.apply_scope_change(&changed, adapter_only) >= 1);
        assert!(!rotated.admit_production_route("route.execute", &changed, 10));
        let mut changed_serializer = scope();
        changed_serializer.feature_flags_and_serializer = Some("serializer-v2".into());
        let mut rotated_serializer = CapabilityRegistry::new();
        rotated_serializer.insert(probe("route.execute", scope(), 1));
        assert!(rotated_serializer.admit_production_route("route.execute", &scope(), 10));
        let serializer_only = ScopeDependencySelector {
            feature_flags_and_serializer: true,
            ..ScopeDependencySelector::none()
        };
        assert!(rotated_serializer.apply_scope_change(&changed_serializer, serializer_only) >= 1);
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
        registry.insert(official);
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
        registry.insert(probe("skill-a", scope(), 1).expires_at(10));
        assert!(registry.admit_production_route("skill-a", &scope(), 9));
        assert!(!registry.admit_production_route("skill-a", &scope(), 10));
        assert!(!registry.admit_production_route("skill-a", &scope(), 11));
    }

    #[test]
    fn future_observations_do_not_admit() {
        let mut registry = CapabilityRegistry::new();
        registry.insert(probe("skill-a", scope(), 20));
        assert!(!registry.admit_production_route("skill-a", &scope(), 10));
        assert!(registry.admit_production_route("skill-a", &scope(), 20));
    }

    #[test]
    fn degraded_evidence_restricts_the_exact_scope() {
        let mut registry = CapabilityRegistry::new();
        registry.insert(probe("skill-a", scope(), 1));
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
        );
        // The superseding degraded record replaces the positive: the route
        // is restricted until fresh positive evidence re-qualifies it.
        assert!(!registry.admit_production_route("skill-a", &scope(), 10));
        registry.insert(probe("skill-a", scope(), 3));
        assert!(registry.admit_production_route("skill-a", &scope(), 10));
    }

    #[test]
    fn scope_change_is_narrowed_by_dependency_selector() {
        let mut registry = CapabilityRegistry::new();
        registry.insert(probe("skill-a", scope(), 1));
        let mut other = scope();
        other.provider_model_route = Some("other/model/auth".into());
        registry.insert(probe("skill-b", other.clone(), 1));
        let mut changed = scope();
        changed.adapter_hash = Some("adapter-hash-2".into());
        let adapter_only = ScopeDependencySelector {
            adapter_hash: true,
            ..ScopeDependencySelector::none()
        };
        // skill-b shares the stale adapter hash, so it stales; a selector
        // naming only the provider route would leave both untouched.
        assert_eq!(registry.apply_scope_change(&changed, adapter_only), 2);
        assert!(registry.is_scope_invalidated(&scope()));
        assert!(registry.is_scope_invalidated(&other));
        let fresh = CapabilityRegistry::new();
        let mut fresh_registry = fresh;
        fresh_registry.insert(probe("skill-a", scope(), 1));
        let provider_only = ScopeDependencySelector {
            provider_model_route: true,
            ..ScopeDependencySelector::none()
        };
        assert_eq!(
            fresh_registry.apply_scope_change(&changed, provider_only),
            0
        );
        assert!(fresh_registry.admit_production_route("skill-a", &scope(), 10));
    }

    #[test]
    fn insert_supersedes_and_evicts_oldest_first() {
        let mut registry = CapabilityRegistry::new();
        registry.insert(probe("skill-a", scope(), 1));
        registry.insert(probe("skill-a", scope(), 2));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.records()[0].observed_at, 2);
        for index in 0..MAX_CAPABILITY_EVIDENCE_RECORDS {
            let mut scoped = scope();
            scoped.runtime_hash = Some(format!("runtime-hash-{index}"));
            registry.insert(probe(&format!("skill-{index}"), scoped, 1));
        }
        assert_eq!(registry.len(), MAX_CAPABILITY_EVIDENCE_RECORDS);
        // The superseded skill-a record (oldest fingerprint order) evicted;
        // the newest insert is retained.
        assert!(
            !registry
                .records()
                .iter()
                .any(|record| record.skill_id == "skill-a")
        );
    }

    #[test]
    fn fresh_evidence_requalifies_an_invalidated_scope() {
        let mut registry = CapabilityRegistry::new();
        registry.insert(probe("skill-a", scope(), 1));
        let mut changed = scope();
        changed.adapter_hash = Some("adapter-hash-2".into());
        assert!(registry.apply_scope_change(&changed, ScopeDependencySelector::all()) >= 1);
        assert!(!registry.admit_production_route("skill-a", &scope(), 10));
        registry.insert(probe("skill-a", scope(), 3));
        assert!(!registry.is_scope_invalidated(&scope()));
        assert!(registry.admit_production_route("skill-a", &scope(), 10));
    }
}
