//! Scoped capability evidence registry (Issue #1957, I3.4).
//!
//! Capability is not a boolean. Each claim carries status, source, a complete
//! route-scope fingerprint, limitations/negative evidence, references,
//! observed time, and expiry. Legacy declarations enter only as
//! `declared` / `imported_legacy_declaration` (via
//! [`eliot_config::legacy_capability_import`]) and never satisfy production
//! admission. Production admission requires fresh exact-fingerprint
//! `probe_passed` or `observed` evidence; exact-fingerprint `broken` or
//! `unsupported` evidence overrides declarations. A runtime, adapter,
//! provider, serializer, or behavior-affecting profile change stales dependent
//! evidence.

#![forbid(unsafe_code)]

use eliot_config::legacy_capability_import::ImportedLegacyEvidence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Claim status for one scoped capability record.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
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

/// Complete route-scope fingerprint for one capability claim.
///
/// Fields the source cannot provide stay `None` (unknown, never inferred).
/// `None` matches only `None` during exact-fingerprint comparison.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
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

/// One evidence-linked capability fact in the canonical registry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEvidenceRecord {
    pub capability: String,
    pub status: CapabilityStatus,
    pub source: CapabilitySource,
    pub scope: RouteScopeFingerprint,
    pub limitations_and_negative_evidence: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub observed_at: u64,
    pub expires_at: Option<u64>,
    pub stale: bool,
}

impl CapabilityEvidenceRecord {
    /// Builds a fresh verified-evidence record (probe/observation path).
    #[must_use]
    pub fn verified(
        capability: &str,
        status: CapabilityStatus,
        source: CapabilitySource,
        scope: RouteScopeFingerprint,
        observed_at: u64,
    ) -> Self {
        Self {
            capability: capability.into(),
            status,
            source,
            scope,
            limitations_and_negative_evidence: Vec::new(),
            evidence_refs: Vec::new(),
            observed_at,
            expires_at: None,
            stale: false,
        }
    }

    /// Returns true when this record is a fresh exact-fingerprint positive
    /// that may admit production work: `probe_passed` or `observed` from a
    /// non-legacy source, not stale.
    #[must_use]
    pub fn is_fresh_positive_for(&self, capability: &str, scope: &RouteScopeFingerprint) -> bool {
        !self.stale
            && self.capability == capability
            && self.scope.exact_match(scope)
            && matches!(
                self.status,
                CapabilityStatus::ProbePassed | CapabilityStatus::Observed
            )
            && !matches!(self.source, CapabilitySource::ImportedLegacyDeclaration)
    }

    /// Returns true when this record is a fresh exact-fingerprint negative
    /// (`broken` or `unsupported`) that overrides declarations.
    #[must_use]
    pub fn is_fresh_negative_for(&self, capability: &str, scope: &RouteScopeFingerprint) -> bool {
        !self.stale
            && self.capability == capability
            && self.scope.exact_match(scope)
            && matches!(
                self.status,
                CapabilityStatus::Broken | CapabilityStatus::Unsupported
            )
    }
}

impl From<&ImportedLegacyEvidence> for CapabilityEvidenceRecord {
    /// Normalizes a legacy import into the canonical registry shape.
    /// The `declared` / `imported_legacy_declaration` semantics are preserved
    /// exactly; unknown scope fields stay unknown.
    fn from(imported: &ImportedLegacyEvidence) -> Self {
        Self {
            capability: imported.capability.clone(),
            status: CapabilityStatus::Declared,
            source: CapabilitySource::ImportedLegacyDeclaration,
            scope: RouteScopeFingerprint {
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
            stale: false,
        }
    }
}

/// Governor-owned canonical registry of scoped capability evidence.
#[derive(Clone, Debug, Default)]
pub struct CapabilityRegistry {
    records: Vec<CapabilityEvidenceRecord>,
}

impl CapabilityRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Inserts one evidence record.
    pub fn insert(&mut self, record: CapabilityEvidenceRecord) {
        self.records.push(record);
    }

    /// Returns all records, including stale and declared-only entries.
    #[must_use]
    pub fn records(&self) -> &[CapabilityEvidenceRecord] {
        &self.records
    }

    /// Production admission for one capability on one exact route scope.
    ///
    /// Requires at least one fresh exact-fingerprint `probe_passed` or
    /// `observed` record from a non-legacy source, and no fresh
    /// exact-fingerprint `broken` or `unsupported` record. Declared/imported
    /// records alone never admit.
    #[must_use]
    pub fn admit_production_route(&self, capability: &str, scope: &RouteScopeFingerprint) -> bool {
        if self
            .records
            .iter()
            .any(|record| record.is_fresh_negative_for(capability, scope))
        {
            return false;
        }
        self.records
            .iter()
            .any(|record| record.is_fresh_positive_for(capability, scope))
    }

    /// Stales every record whose scope no longer exactly equals `current`.
    ///
    /// A runtime, adapter, provider, serializer, or behavior-affecting profile
    /// change therefore invalidates dependent positive evidence instead of
    /// leaving it authorizing production work. Returns the count of newly
    /// staled records.
    pub fn invalidate_on_scope_change(&mut self, current: &RouteScopeFingerprint) -> usize {
        let mut newly_staled = 0;
        for record in &mut self.records {
            if !record.stale && !record.scope.exact_match(current) {
                record.stale = true;
                newly_staled += 1;
            }
        }
        newly_staled
    }
}

#[cfg(test)]
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

    #[test]
    fn capability_evidence_acceptance_1957() {
        // Legacy declaration appears only as declared/imported_legacy and
        // cannot admit a production route.
        let imported = import_legacy_declaration(&LegacyCapabilityDeclaration {
            capability: "route.execute".into(),
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
        assert!(!registry.admit_production_route("route.execute", &scope()));

        // A fresh exact-fingerprint probe_passed record admits the same route.
        registry.insert(CapabilityEvidenceRecord::verified(
            "route.execute",
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            scope(),
            1,
        ));
        assert!(registry.admit_production_route("route.execute", &scope()));

        // An exact-fingerprint broken record subsequently blocks it.
        registry.insert(CapabilityEvidenceRecord::verified(
            "route.execute",
            CapabilityStatus::Broken,
            CapabilitySource::ReproducedFailure,
            scope(),
            2,
        ));
        assert!(!registry.admit_production_route("route.execute", &scope()));

        // Adapter-hash or serializer change stales the earlier positive
        // evidence: a registry holding only legacy + positive evidence no
        // longer admits after the dependency change.
        let mut rotated = CapabilityRegistry::new();
        rotated.insert(CapabilityEvidenceRecord::from(&imported));
        rotated.insert(CapabilityEvidenceRecord::verified(
            "route.execute",
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            scope(),
            1,
        ));
        assert!(rotated.admit_production_route("route.execute", &scope()));
        let mut changed = scope();
        changed.adapter_hash = Some("adapter-hash-2".into());
        assert!(rotated.invalidate_on_scope_change(&changed) >= 1);
        assert!(!rotated.admit_production_route("route.execute", &changed));
        let mut changed_serializer = scope();
        changed_serializer.feature_flags_and_serializer = Some("serializer-v2".into());
        let mut rotated_serializer = CapabilityRegistry::new();
        rotated_serializer.insert(CapabilityEvidenceRecord::verified(
            "route.execute",
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            scope(),
            1,
        ));
        assert!(rotated_serializer.admit_production_route("route.execute", &scope()));
        assert!(rotated_serializer.invalidate_on_scope_change(&changed_serializer) >= 1);
        assert!(!rotated_serializer.admit_production_route("route.execute", &changed_serializer));
    }
}
