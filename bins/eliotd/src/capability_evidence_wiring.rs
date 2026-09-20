//! Minimal `eliotd` Governor wiring for scoped capability evidence (#1957).
//!
//! The canonical registry and evidence semantics live in `eliot-governor`;
//! legacy normalization lives in `eliot-config`. This module only exposes the
//! Governor-owned admission view to the daemon composition root: production
//! admission requires fresh exact-fingerprint `probe_passed` or `observed`
//! evidence, never a `declared` / `imported_legacy_declaration` record.

use eliot_governor::{
    CapabilityEvidenceRecord, CapabilityRegistry, CapabilitySource, CapabilityStatus,
    RouteScopeFingerprint, legacy_capability_import,
};

pub use eliot_governor::legacy_capability_import::{
    ImportedLegacyEvidence, LegacyCapabilityDeclaration, LegacyImportError, LegacyScopeFingerprint,
    import_legacy_declaration,
};
pub use eliot_governor::{
    CapabilityEvidenceRecord as GovernorCapabilityEvidenceRecord,
    CapabilityRegistry as GovernorCapabilityRegistry, CapabilitySource as GovernorCapabilitySource,
    CapabilityStatus as GovernorCapabilityStatus,
    RouteScopeFingerprint as GovernorRouteScopeFingerprint,
};

/// Daemon-held Governor capability admission view.
#[derive(Debug, Default)]
pub struct GovernorCapabilityAdmission {
    registry: CapabilityRegistry,
}

impl GovernorCapabilityAdmission {
    /// Creates an empty admission view.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: CapabilityRegistry::new(),
        }
    }

    /// Returns the underlying canonical registry.
    #[must_use]
    pub const fn registry(&self) -> &CapabilityRegistry {
        &self.registry
    }

    /// Inserts one canonical evidence record.
    pub fn insert(&mut self, record: CapabilityEvidenceRecord) {
        self.registry.insert(record);
    }

    /// Imports one legacy declaration as `declared/imported_legacy`.
    ///
    /// # Errors
    ///
    /// Returns [`legacy_capability_import::LegacyImportError`] when the legacy
    /// declaration is blank.
    pub fn import_legacy(
        &mut self,
        declaration: &LegacyCapabilityDeclaration,
    ) -> Result<(), legacy_capability_import::LegacyImportError> {
        let imported = import_legacy_declaration(declaration)?;
        self.registry
            .insert(CapabilityEvidenceRecord::from(&imported));
        Ok(())
    }

    /// Production admission for one capability on one exact route scope.
    #[must_use]
    pub fn admit_production_route(&self, capability: &str, scope: &RouteScopeFingerprint) -> bool {
        self.registry.admit_production_route(capability, scope)
    }

    /// Stales dependent evidence after a runtime/adapter/provider/serializer
    /// or behavior-affecting profile change. Returns newly staled count.
    pub fn apply_scope_change(&mut self, current: &RouteScopeFingerprint) -> usize {
        self.registry.invalidate_on_scope_change(current)
    }

    /// Builds a fresh verified-evidence record for the probe path.
    #[must_use]
    pub fn verified_record(
        capability: &str,
        status: CapabilityStatus,
        source: CapabilitySource,
        scope: RouteScopeFingerprint,
        observed_at: u64,
    ) -> CapabilityEvidenceRecord {
        CapabilityEvidenceRecord::verified(capability, status, source, scope, observed_at)
    }
}
