//! Canonical startup sequence and readiness gates (Implements #1967).
//!
//! Traceability:
//! - `I01-11-startup-algorithm.md` :: I1.11 steps 1-11 define the single
//!   ordered startup state machine represented here.
//! - `I01-10-service-health-state-model.md` :: I1.10 keeps readiness
//!   capability-scoped; front-door readiness never implies Material/Critical
//!   authority.
//! - `I01-13-kernel-unavailability.md` :: I1.13 forbids new canonical writes
//!   and external Material authority while mandatory recovery evidence is
//!   incomplete.
//! - `A07-07-governance-profile.md` :: A7.7 owns the only ceiling scale; the
//!   startup coordinator reports a ceiling but never invents authority.
//!
//! Ordinary module: pure ordered gating only. No I/O, no ORS/store/daemon
//! mechanics, no credentials. `KernelComposition` owns the single instance
//! and consults it from normal-write and Material/Critical admission paths.

use serde::Serialize;

/// Ordered I1.11 startup step (1-11). Step 0 means nothing completed.
pub const STARTUP_FIRST_STEP: u8 = 1;
/// Final I1.11 step: watchdog supervision evidence confirmed.
pub const STARTUP_FINAL_STEP: u8 = 11;

/// Fixed name for one I1.11 step. Unknown numbers map to `"unknown"`.
#[must_use]
pub const fn startup_step_name(step: u8) -> &'static str {
    match step {
        0 => "not-started",
        1 => "host-validated",
        2 => "kernel-started",
        3 => "ors-opened",
        4 => "blob-manifest-validated",
        5 => "store-probed",
        6 => "operations-reconciled",
        7 => "eliotd-handshake",
        8 => "config-mirrors-rebuilt",
        9 => "capabilities-evaluated",
        10 => "front-door-ready",
        11 => "supervision-confirmed",
        _ => "unknown",
    }
}

/// Named mandatory startup prerequisite. The fixed vocabulary is the rejection
/// identity surfaced when a normal canonical write or Material authority is
/// refused while startup is incomplete.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartupPrerequisite {
    /// I1.11 step 6: pending/unknown operations reconciled before normal writes.
    OrsReconciliation,
    /// I1.11 step 5: independent canonical-store readiness/schema probes.
    StoreSchemaProbe,
    /// I1.11 step 3: ORS integrity anchor, Generation Registry, epoch recovery.
    EpochRecovery,
    /// I1.11 step 11: watchdog supervision/enforcement evidence.
    SupervisionEvidence,
}

impl StartupPrerequisite {
    /// Fixed rejection identity for this prerequisite.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OrsReconciliation => "ors-reconciliation",
            Self::StoreSchemaProbe => "store-schema-probe",
            Self::EpochRecovery => "epoch-recovery",
            Self::SupervisionEvidence => "supervision-evidence",
        }
    }

    /// I1.11 step that completes this prerequisite.
    #[must_use]
    pub const fn completing_step(self) -> u8 {
        match self {
            Self::EpochRecovery => 3,
            Self::StoreSchemaProbe => 5,
            Self::OrsReconciliation => 6,
            Self::SupervisionEvidence => 11,
        }
    }
}

/// Authority ceiling reported by startup status. While any mandatory gate is
/// incomplete the ceiling is capped at [`AuthorityCeiling::LowImpact`]:
/// attach, inspection, and policy-allowed low-impact work only. Material and
/// Critical rise only through the Governance Profile once every mandatory
/// gate has passed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityCeiling {
    /// Inspection and attach only (startup has not reached front-door).
    Inspection,
    /// Front-door readiness: attach, inspection, policy-allowed low-impact.
    LowImpact,
    /// Governance Profile permits Material authority.
    Material,
    /// Governance Profile permits Critical authority.
    Critical,
}

impl AuthorityCeiling {
    /// Fixed status vocabulary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspection => "inspection",
            Self::LowImpact => "low-impact",
            Self::Material => "material",
            Self::Critical => "critical",
        }
    }

    fn allows_material(self) -> bool {
        matches!(self, Self::Material | Self::Critical)
    }
}

/// Observation axis of the Governance Profile (A7.7).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GovernanceObservation {
    /// No independent observation.
    #[default]
    Absent,
    /// Self-reported only.
    SelfReported,
    /// Host-observed.
    HostObserved,
    /// Independently observed.
    IndependentlyObserved,
}

/// Enforcement axis of the Governance Profile (A7.7).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GovernanceEnforcement {
    /// No enforcement.
    #[default]
    Absent,
    /// Advisory only.
    Advisory,
    /// Interceptable.
    Interceptable,
    /// Enforced.
    Enforced,
}

/// Supervision axis of the Governance Profile (A7.7).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GovernanceSupervision {
    /// No supervision.
    #[default]
    Absent,
    /// Self-monitored.
    SelfMonitored,
    /// Watchdog-observed.
    WatchdogObserved,
    /// Independently supervised.
    IndependentlySupervised,
}

/// Minimal Governance Profile (A7.7 vector). The ceiling is the weakest
/// relevant axis: no single strong axis promotes authority by itself.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize)]
pub struct GovernanceProfile {
    /// Observation axis.
    pub observation: GovernanceObservation,
    /// Enforcement axis.
    pub enforcement: GovernanceEnforcement,
    /// Supervision axis.
    pub supervision: GovernanceSupervision,
}

impl GovernanceProfile {
    /// Lowest profile: no observation, enforcement, or supervision.
    #[must_use]
    pub const fn minimal() -> Self {
        Self {
            observation: GovernanceObservation::Absent,
            enforcement: GovernanceEnforcement::Absent,
            supervision: GovernanceSupervision::Absent,
        }
    }

    /// Full profile: independently observed, enforced, independently
    /// supervised. The only profile that permits Critical.
    #[must_use]
    pub const fn full() -> Self {
        Self {
            observation: GovernanceObservation::IndependentlyObserved,
            enforcement: GovernanceEnforcement::Enforced,
            supervision: GovernanceSupervision::IndependentlySupervised,
        }
    }

    /// Material-grade profile: host-observed, interceptable,
    /// watchdog-observed. Permits Material but never Critical.
    #[must_use]
    pub const fn material_grade() -> Self {
        Self {
            observation: GovernanceObservation::HostObserved,
            enforcement: GovernanceEnforcement::Interceptable,
            supervision: GovernanceSupervision::WatchdogObserved,
        }
    }

    /// Ceiling allowed by this profile alone. Startup completeness is applied
    /// separately by [`StartupCoordinator::authority_ceiling`].
    #[must_use]
    pub const fn ceiling(self) -> AuthorityCeiling {
        match (self.observation, self.enforcement, self.supervision) {
            (
                GovernanceObservation::IndependentlyObserved,
                GovernanceEnforcement::Enforced,
                GovernanceSupervision::IndependentlySupervised,
            ) => AuthorityCeiling::Critical,
            (
                GovernanceObservation::HostObserved | GovernanceObservation::IndependentlyObserved,
                GovernanceEnforcement::Interceptable | GovernanceEnforcement::Enforced,
                GovernanceSupervision::WatchdogObserved
                | GovernanceSupervision::IndependentlySupervised,
            ) => AuthorityCeiling::Material,
            _ => AuthorityCeiling::LowImpact,
        }
    }
}

/// Rejection for a normal canonical write or Material/Critical authority
/// request while a mandatory startup prerequisite is incomplete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupRejection {
    prerequisite: StartupPrerequisite,
    message: String,
}

impl StartupRejection {
    fn new(prerequisite: StartupPrerequisite, kind: &'static str) -> Self {
        Self {
            prerequisite,
            message: format!(
                "{kind} rejected: startup prerequisite '{}' is incomplete (I1.11 step {})",
                prerequisite.name(),
                prerequisite.completing_step(),
            ),
        }
    }

    /// Named unmet prerequisite (fixed vocabulary).
    #[must_use]
    pub const fn prerequisite(&self) -> StartupPrerequisite {
        self.prerequisite
    }

    /// Fixed prerequisite identity.
    #[must_use]
    pub fn prerequisite_name(&self) -> &'static str {
        self.prerequisite.name()
    }

    /// Human-readable rejection carrying the named prerequisite.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for StartupRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StartupRejection {}

/// Structured startup status record: completed step, blocking prerequisite,
/// degraded optional capabilities, and current authority ceiling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StartupStatus {
    /// Highest contiguously completed I1.11 step (0-11).
    pub completed_step: u8,
    /// Fixed name of `completed_step`.
    pub completed_step_name: &'static str,
    /// First incomplete mandatory prerequisite, if any.
    pub blocking_prerequisite: Option<&'static str>,
    /// Degraded optional capabilities (blob large-payload capture,
    /// optional capability set). Degradation never blocks Material by
    /// itself; it is reported here.
    pub degraded_capabilities: Vec<&'static str>,
    /// Current authority ceiling for the supplied Governance Profile.
    pub authority_ceiling: &'static str,
    /// True once step 10 (front-door readiness published) is reached.
    pub front_door_ready: bool,
}

/// Explicit startup coordinator whose transitions correspond to I1.11 steps
/// 1-11. Steps must complete in order; out-of-order completion fails closed.
#[allow(
    clippy::struct_excessive_bools,
    reason = "four mandatory gates plus two degraded flags are the I1.11 acceptance vocabulary; a state machine split would obscure the named prerequisites"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartupCoordinator {
    completed_step: u8,
    ors_reconciled: bool,
    store_schema_probed: bool,
    epoch_recovered: bool,
    supervision_evidence_complete: bool,
    blob_degraded: bool,
    capability_degraded: bool,
}

impl Default for StartupCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl StartupCoordinator {
    /// New coordinator with no steps completed and every mandatory gate open.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            completed_step: 0,
            ors_reconciled: false,
            store_schema_probed: false,
            epoch_recovered: false,
            supervision_evidence_complete: false,
            blob_degraded: false,
            capability_degraded: false,
        }
    }

    /// Highest contiguously completed I1.11 step.
    #[must_use]
    pub const fn completed_step(&self) -> u8 {
        self.completed_step
    }

    /// Fixed name of the completed step.
    #[must_use]
    pub fn completed_step_name(&self) -> &'static str {
        startup_step_name(self.completed_step)
    }

    /// First incomplete mandatory prerequisite in canonical order.
    #[must_use]
    pub const fn blocking_prerequisite(&self) -> Option<StartupPrerequisite> {
        if !self.ors_reconciled {
            Some(StartupPrerequisite::OrsReconciliation)
        } else if !self.store_schema_probed {
            Some(StartupPrerequisite::StoreSchemaProbe)
        } else if !self.epoch_recovered {
            Some(StartupPrerequisite::EpochRecovery)
        } else if !self.supervision_evidence_complete {
            Some(StartupPrerequisite::SupervisionEvidence)
        } else {
            None
        }
    }

    /// Degraded optional capabilities (fixed vocabulary).
    #[must_use]
    pub fn degraded_capabilities(&self) -> Vec<&'static str> {
        let mut degraded = Vec::new();
        if self.blob_degraded {
            degraded.push("blob-large-payload-capture");
        }
        if self.capability_degraded {
            degraded.push("optional-capability-set");
        }
        degraded
    }

    /// True once step 10 is reached. Front-door readiness permits attach,
    /// inspection, and policy-allowed low-impact work only; it never unlocks
    /// Material/Critical authority by itself.
    #[must_use]
    pub const fn is_front_door_ready(&self) -> bool {
        self.completed_step >= 10
    }

    /// Current authority ceiling for one Governance Profile. Any incomplete
    /// mandatory gate caps the ceiling at low-impact; a complete startup
    /// reports exactly the profile ceiling and nothing higher.
    #[must_use]
    pub const fn authority_ceiling(&self, profile: GovernanceProfile) -> AuthorityCeiling {
        if self.blocking_prerequisite().is_some() {
            return AuthorityCeiling::LowImpact;
        }
        profile.ceiling()
    }

    /// Structured status record for the supplied Governance Profile.
    #[must_use]
    pub fn startup_status(&self, profile: GovernanceProfile) -> StartupStatus {
        StartupStatus {
            completed_step: self.completed_step,
            completed_step_name: self.completed_step_name(),
            blocking_prerequisite: self.blocking_prerequisite().map(StartupPrerequisite::name),
            degraded_capabilities: self.degraded_capabilities(),
            authority_ceiling: self.authority_ceiling(profile).as_str(),
            front_door_ready: self.is_front_door_ready(),
        }
    }

    /// Inspection is always allowed where front-door policy allows it;
    /// startup gates never fence inspection itself.
    #[must_use]
    pub const fn admit_inspection(&self) -> bool {
        true
    }

    /// Normal canonical-write admission. Rejects with the named unmet
    /// prerequisite while any mandatory gate is incomplete.
    ///
    /// # Errors
    ///
    /// Returns the blocking [`StartupRejection`] naming the unmet
    /// prerequisite.
    pub fn admit_normal_write(&self) -> Result<(), StartupRejection> {
        if let Some(gate) = self.blocking_prerequisite() {
            return Err(StartupRejection::new(gate, "normal canonical write"));
        }
        Ok(())
    }

    /// Material/Critical authority admission for one Governance Profile.
    /// Rejects with the named unmet startup prerequisite first; once startup
    /// is complete the profile ceiling alone decides.
    ///
    /// # Errors
    ///
    /// Returns the blocking [`StartupRejection`] or a profile-ceiling
    /// rejection when the profile does not permit Material authority.
    pub fn admit_material_authority(
        &self,
        profile: GovernanceProfile,
    ) -> Result<(), StartupRejection> {
        if let Some(gate) = self.blocking_prerequisite() {
            return Err(StartupRejection::new(gate, "material authority"));
        }
        if self.authority_ceiling(profile).allows_material() {
            Ok(())
        } else {
            Err(StartupRejection {
                prerequisite: StartupPrerequisite::SupervisionEvidence,
                message: format!(
                    "material authority rejected: governance profile ceiling is '{}'; requires a material-grade profile",
                    self.authority_ceiling(profile).as_str(),
                ),
            })
        }
    }

    /// Records blob large-payload degradation (I1.11 step 4). A failed blob
    /// probe degrades only large-payload capture and never blocks Material.
    pub const fn note_blob_degraded(&mut self) {
        self.blob_degraded = true;
    }

    /// Records optional-capability degradation (I1.11 step 9). Optional
    /// failures become visible degradation, never silent Material.
    pub const fn note_capability_degraded(&mut self) {
        self.capability_degraded = true;
    }

    fn require_next(&self, step: u8) -> Result<(), String> {
        if step == self.completed_step.saturating_add(1) {
            Ok(())
        } else {
            Err(format!(
                "startup step {step} requires completed step {}, observed {}",
                self.completed_step.saturating_add(1),
                self.completed_step,
            ))
        }
    }

    fn complete_ordered(&mut self, step: u8) -> Result<(), String> {
        self.require_next(step)?;
        if step > STARTUP_FINAL_STEP {
            return Err(format!("startup step {step} is outside I1.11 steps 1-11"));
        }
        self.completed_step = step;
        Ok(())
    }

    /// Completes one I1.11 step in order, setting the mandatory gate that
    /// step proves. Steps without a mandatory gate only advance the ordered
    /// cursor. Out-of-order or out-of-range steps fail closed.
    ///
    /// # Errors
    ///
    /// Returns a fixed-shape ordering error when `step` is not exactly the
    /// next expected step or lies outside 1-11.
    pub fn complete_step(&mut self, step: u8) -> Result<(), String> {
        match step {
            1 | 2 | 4 | 7..=10 => self.complete_ordered(step),
            3 => {
                self.complete_ordered(step)?;
                self.epoch_recovered = true;
                Ok(())
            }
            5 => {
                self.complete_ordered(step)?;
                self.store_schema_probed = true;
                Ok(())
            }
            6 => {
                self.complete_ordered(step)?;
                self.ors_reconciled = true;
                Ok(())
            }
            11 => {
                self.complete_ordered(step)?;
                self.supervision_evidence_complete = true;
                Ok(())
            }
            _ => Err(format!("startup step {step} is outside I1.11 steps 1-11")),
        }
    }

    /// Completes every mandatory gate in I1.11 order (1-11). Test and
    /// composition-recovery helper; production advances step by step as each
    /// probe/handshake actually completes.
    ///
    /// # Errors
    ///
    /// Returns the ordering error if the coordinator has already advanced
    /// past the start.
    pub fn complete_all_mandatory(&mut self) -> Result<(), String> {
        for step in STARTUP_FIRST_STEP..=STARTUP_FINAL_STEP {
            self.complete_step(step)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn coordinator_at_step(step: u8) -> StartupCoordinator {
        let mut coordinator = StartupCoordinator::new();
        for next in STARTUP_FIRST_STEP..=step {
            coordinator
                .complete_step(next)
                .expect("ordered startup completion");
        }
        coordinator
    }

    #[test]
    fn incomplete_startup_rejects_write_and_material_but_allows_inspection() {
        let coordinator = coordinator_at_step(4);
        assert!(coordinator.admit_inspection());
        let write = coordinator
            .admit_normal_write()
            .expect_err("normal write must fail before step 6");
        assert_eq!(
            write.prerequisite_name(),
            "ors-reconciliation",
            "rejection must name the unmet prerequisite, got: {write}",
        );
        let material = coordinator
            .admit_material_authority(GovernanceProfile::full())
            .expect_err("material must fail before step 6");
        assert_eq!(material.prerequisite_name(), "ors-reconciliation");
        let status = coordinator.startup_status(GovernanceProfile::full());
        assert_eq!(status.completed_step, 4);
        assert_eq!(
            status.blocking_prerequisite,
            Some("ors-reconciliation"),
            "status must report the blocking prerequisite",
        );
        assert_eq!(status.authority_ceiling, "low-impact");
        assert!(!status.front_door_ready);
    }

    #[test]
    fn each_mandatory_gate_names_its_prerequisite() {
        let mut full = coordinator_at_step(11);
        assert!(full.admit_normal_write().is_ok());
        for gate in [
            StartupPrerequisite::OrsReconciliation,
            StartupPrerequisite::StoreSchemaProbe,
            StartupPrerequisite::EpochRecovery,
            StartupPrerequisite::SupervisionEvidence,
        ] {
            let mut partial = full.clone();
            match gate {
                StartupPrerequisite::OrsReconciliation => {
                    partial.ors_reconciled = false;
                }
                StartupPrerequisite::StoreSchemaProbe => {
                    partial.store_schema_probed = false;
                }
                StartupPrerequisite::EpochRecovery => {
                    partial.epoch_recovered = false;
                }
                StartupPrerequisite::SupervisionEvidence => {
                    partial.supervision_evidence_complete = false;
                }
            }
            let rejection = partial
                .admit_normal_write()
                .expect_err("gate must block normal writes");
            assert_eq!(rejection.prerequisite(), gate);
            assert!(
                rejection.message().contains(gate.name()),
                "message must name '{}', got: {}",
                gate.name(),
                rejection.message(),
            );
            assert!(partial.admit_inspection());
        }
        let _ = &mut full;
    }

    #[test]
    fn complete_startup_reports_final_step_and_profile_ceiling_only() {
        let coordinator = coordinator_at_step(11);
        let status_full = coordinator.startup_status(GovernanceProfile::full());
        assert_eq!(status_full.completed_step, 11);
        assert_eq!(status_full.completed_step_name, "supervision-confirmed");
        assert_eq!(status_full.blocking_prerequisite, None);
        assert_eq!(status_full.authority_ceiling, "critical");
        assert!(status_full.front_door_ready);
        assert!(coordinator.admit_normal_write().is_ok());
        assert!(
            coordinator
                .admit_material_authority(GovernanceProfile::full())
                .is_ok()
        );
        let status_minimal = coordinator.startup_status(GovernanceProfile::minimal());
        assert_eq!(status_minimal.completed_step, 11);
        assert_eq!(status_minimal.authority_ceiling, "low-impact");
        assert!(
            coordinator
                .admit_material_authority(GovernanceProfile::minimal())
                .is_err(),
            "ceiling must rise per Governance Profile only",
        );
    }
}
