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
//! - `I01-05-demand-start-observable-use-supervision-and-idle-shutdown.md` ::
//!   I1.5 step "verify the current Watchdog supervision epoch and responsiveness"
//!   and "if renewal cannot be proved, coverage ends at expiry and is reported
//!   honestly" — the supervision step is an owner observation with a finite
//!   validity interval, not retained text.
//! - `I08-02-independent-observation-routes.md` :: I8.2 — an observation proves
//!   event existence, and its coverage is explicit; an absent or expired
//!   observation leaves coverage unestablished rather than presumed.
//!
//! Ordinary module: pure ordered gating only. No I/O, no ORS/store/daemon
//! mechanics, no credentials. `KernelComposition` owns the single instance
//! and consults it from normal-write and Material/Critical admission paths.

use eliot_contracts::StateFence;
use eliot_platform::PlatformHandle;
use eliot_runtime_contracts::SupervisionJournalEpoch;
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

    /// Test-only ceiling probe: production never mints a profile, so the only
    /// callers are the unit tests below.
    #[cfg(test)]
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
    ///
    /// Minting is crate-local: production gates admit only the recorded
    /// Governor-issued projection, never a caller-minted profile.
    #[must_use]
    pub(crate) const fn full() -> Self {
        Self {
            observation: GovernanceObservation::IndependentlyObserved,
            enforcement: GovernanceEnforcement::Enforced,
            supervision: GovernanceSupervision::IndependentlySupervised,
        }
    }

    /// Material-grade profile: host-observed, interceptable,
    /// watchdog-observed. Permits Material but never Critical.
    ///
    /// Minting is crate-local: production gates admit only the recorded
    /// Governor-issued projection, never a caller-minted profile.
    #[must_use]
    pub(crate) const fn material_grade() -> Self {
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

/// Maps the Governor owner's exact authorization axes to this crate's
/// existing three-axis profile (I7.16, #1935 AUD1).
///
/// No third vocabulary is introduced: the inputs name the owner's
/// `GovernanceProfile::authorizes` axes exactly, and the output is the
/// existing [`GovernanceProfile`] vector. The ladder is fail-closed: only a
/// verified profile authorizing both enforcement and complete-coverage
/// operations projects to [`GovernanceProfile::full`]; verified enforcement
/// without complete coverage projects to
/// [`GovernanceProfile::material_grade`]; anything weaker (unverified,
/// observed-but-unenforced, incomplete) projects to
/// [`GovernanceProfile::minimal`], so observed-but-unenforced coverage can
/// never admit Material authority.
fn governor_authorization_axes_to_profile(
    verified: bool,
    authorizes_enforcement: bool,
    authorizes_complete_coverage_ops: bool,
) -> GovernanceProfile {
    if verified && authorizes_enforcement && authorizes_complete_coverage_ops {
        GovernanceProfile::full()
    } else if verified && authorizes_enforcement {
        GovernanceProfile::material_grade()
    } else {
        GovernanceProfile::minimal()
    }
}

/// Governor-issued authority projection (I7.16, #1935 AUD1).
///
/// Projection of the Governor-owned revisioned `GovernanceProfile`
/// (`eliot-integration-coverage::GovernorCoverageDerivation`) across the
/// authenticated boundary: the exact owner revision and exact active
/// fingerprint plus the authorization axes in this crate's existing
/// three-axis (A7.7) vocabulary. No third vocabulary is introduced:
/// `revision`/`fingerprint` name the owner binding exactly as the owner
/// names it, and `profile` is the existing [`GovernanceProfile`] vector.
///
/// A recorded projection is the only profile the Material/Critical gates
/// admit under. Authority issued under one revision is rejected once a new
/// revision is recorded, so coverage loss revokes dependent authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernorIssuedAuthority {
    /// Exact owner derivation revision this projection was issued under.
    revision: u64,
    /// Exact active host/adapter fingerprint the owner derived for.
    fingerprint: String,
    /// Authorization axes in the existing three-axis vocabulary.
    profile: GovernanceProfile,
}

impl GovernorIssuedAuthority {
    /// Exact owner revision this projection was issued under.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Exact active fingerprint the owner derived for.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Authorization axes in the existing three-axis vocabulary.
    #[must_use]
    pub const fn profile(&self) -> GovernanceProfile {
        self.profile
    }
}

/// Rejection-shape validation for a Governor-issued fingerprint, mirroring
/// the owner's text rule: the binding must name the exact active
/// fingerprint, never blank or control-carrying text.
fn validate_governor_fingerprint(fingerprint: &str) -> Result<(), String> {
    if fingerprint.trim().is_empty() || fingerprint.chars().any(char::is_control) {
        return Err(
            "governor authority fingerprint must name the exact active fingerprint".to_owned(),
        );
    }
    Ok(())
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
    /// Retained independent Watchdog supervision observations, current first.
    ///
    /// I1.5 (#1750): a superseded or contradicted observation is a fact that is
    /// kept, not overwritten, so the window in which the branch changed is
    /// inspectable after it happened. Inspection only: this projection never
    /// gates, and no decision reads it.
    pub supervision_observations: Vec<WatchdogSupervisionObservation>,
}

/// One independent Watchdog supervision observation, bound to the exact
/// incarnation the observation owner saw, to the exact candidate contour and
/// consumer State Fence it was observed under, and to the moment it was taken.
///
/// I1.5 (#1750): a supervision claim is not a retained string. It is an
/// owner-produced observation that carries its own observation time, its own
/// progress position and a finite validity interval. The closed shape of the
/// carrier is proven once, where the record is created; currency, contour
/// binding and fence binding are proven at every consumer, on the Kernel
/// supervision clock. A renewed signed lease advances no field here, so a lease
/// renewal can never be counted as a physical observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WatchdogSupervisionObservation {
    /// The exact live SCM Watchdog incarnation digest the owner observed:
    /// `host-scm-watchdog:{pid}:{start}:{image_sha256}`.
    pub incarnation: PlatformHandle,
    /// Digest of the exact candidate contour this observation was taken under.
    pub candidate_digest: PlatformHandle,
    /// The exact consumer State Fence this observation is bound to.
    pub state_fence: StateFence,
    /// The Watchdog epoch of the contour this observation was taken under. The
    /// signed supervision lease is joined to this epoch, not to a number copied
    /// out of a lease, so the observation is consumed by the coverage
    /// comparison rather than sitting beside it.
    pub watchdog_epoch: SupervisionJournalEpoch,
    /// Observation time on the Kernel supervision clock, in milliseconds. This
    /// is the causal moment the owner observation was accepted, not a value the
    /// observation carried about itself.
    pub observed_at_ms: u64,
    /// Monotonic count of independent owner observations accepted by this
    /// coordinator. Only [`StartupCoordinator::record_live_supervision_evidence`]
    /// advances it, so re-reading retained text or renewing a lease cannot
    /// move the frontier.
    pub progress_frontier: u64,
    /// Finite validity interval in milliseconds, supplied by the single
    /// supervision timing owner rather than invented here.
    pub valid_for_ms: u64,
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
    observed_steps: u16,
    ors_reconciled: bool,
    store_schema_probed: bool,
    epoch_recovered: bool,
    supervision_evidence_complete: bool,
    /// The current independent Watchdog supervision observation: exact
    /// incarnation, contour, consumer fence, observed Watchdog epoch,
    /// observation time, progress position and finite validity interval. It is
    /// withdrawn with the revocable step, so a supervision claim can never
    /// outlive the observation that established it and can never be asserted
    /// from lease bookkeeping alone.
    current_supervision_observation: Option<WatchdogSupervisionObservation>,
    /// The observation the current one superseded or contradicted. It is kept
    /// as a fact and never overwritten, and it never gates anything.
    superseded_supervision_observation: Option<WatchdogSupervisionObservation>,
    /// Monotonic count of independent owner observations accepted. Only
    /// [`Self::record_live_supervision_evidence`] advances it, and contour
    /// revocation leaves it alone: the number of physical observations is a
    /// property of this Kernel, not of one activation contour.
    supervision_progress_frontier: u64,
    /// Current Governor-issued authority projection (I7.16, #1935 AUD1).
    /// `None` until the Governor derivation is first recorded across the
    /// authenticated boundary; while `None` every Material/Critical gate
    /// refuses. A newer recorded revision supersedes (revokes) the older
    /// one: admission binds to the exact current revision and fingerprint.
    governor_authority: Option<GovernorIssuedAuthority>,
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
    pub(crate) const fn new() -> Self {
        Self {
            completed_step: 0,
            observed_steps: 0,
            ors_reconciled: false,
            store_schema_probed: false,
            epoch_recovered: false,
            supervision_evidence_complete: false,
            current_supervision_observation: None,
            superseded_supervision_observation: None,
            supervision_progress_frontier: 0,
            governor_authority: None,
            blob_degraded: false,
            capability_degraded: false,
        }
    }

    /// Highest contiguously completed I1.11 step.
    #[cfg(test)]
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
        // The named gates are only satisfied by the contiguous I1.11 cursor.
        // A later owner observation may be retained in `observed_steps`, but it
        // cannot make an earlier missing Host/kernel/blob/mirror/capability
        // transition disappear. Checking the cursor before the gate flags is
        // what keeps out-of-order evidence fail-closed.
        if self.completed_step < 3 || !self.epoch_recovered {
            Some(StartupPrerequisite::EpochRecovery)
        } else if self.completed_step < 5 || !self.store_schema_probed {
            Some(StartupPrerequisite::StoreSchemaProbe)
        } else if self.completed_step < 6 || !self.ors_reconciled {
            Some(StartupPrerequisite::OrsReconciliation)
        } else if self.completed_step < 11 || !self.supervision_evidence_complete {
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
            supervision_observations: self.retained_supervision_observations(),
        }
    }

    /// The retained independent Watchdog supervision observations, current
    /// first. A superseded or contradicted observation is a fact that is kept,
    /// never overwritten. Inspection only: no decision reads this.
    fn retained_supervision_observations(&self) -> Vec<WatchdogSupervisionObservation> {
        let mut retained = Vec::with_capacity(2);
        retained.extend(self.current_supervision_observation.clone());
        retained.extend(self.superseded_supervision_observation.clone());
        retained
    }

    /// Inspection is admitted only after I1.11 step 10 publishes front-door
    /// readiness; control-plane bootstrap and evidence-producing worker routes
    /// are admitted by their dedicated boundaries.
    #[must_use]
    pub const fn admit_inspection(&self) -> bool {
        self.is_front_door_ready()
    }

    /// Normal canonical-write admission. Rejects with the named unmet
    /// prerequisite while any mandatory gate is incomplete.
    ///
    /// # Errors
    ///
    /// Returns the blocking [`StartupRejection`] naming the unmet
    /// prerequisite.
    pub(crate) fn admit_normal_write(&self) -> Result<(), StartupRejection> {
        if let Some(gate) = self.blocking_prerequisite() {
            return Err(StartupRejection::new(gate, "normal canonical write"));
        }
        Ok(())
    }

    /// Queued-attach release admission (I1.11 step 10: "Kernel publishes
    /// front-door readiness and releases queued attaches").
    ///
    /// The attach queue holds requests that arrived before the ordered startup
    /// cursor reached step 10. Releasing one is exactly the front-door
    /// publication, so the decision reads the same
    /// [`Self::is_front_door_ready`] field [`Self::startup_status`] publishes as
    /// `front_door_ready` — there is no second readiness fact, no latched
    /// queue-side copy, and no independent queue check that could drift from
    /// the ordered gate. Step 10 is only reachable through the contiguous I1.11
    /// cursor, so reaching it also proves steps 1-9 (including required
    /// capability evaluation) completed.
    ///
    /// The refusal reuses the existing [`StartupRejection`] and the existing
    /// [`StartupPrerequisite`] vocabulary unchanged: while step 10 is
    /// unreached, `blocking_prerequisite()` already names the first incomplete
    /// mandatory gate, and a refusal is never reported as success.
    ///
    /// # Errors
    ///
    /// Returns the blocking [`StartupRejection`] naming the unmet
    /// prerequisite.
    pub(crate) fn admit_queued_attach_release(&self) -> Result<(), StartupRejection> {
        if self.is_front_door_ready() {
            return Ok(());
        }
        let gate = self
            .blocking_prerequisite()
            .unwrap_or(StartupPrerequisite::OrsReconciliation);
        Err(StartupRejection::new(gate, "queued attach release"))
    }

    /// Material/Critical authority admission for one Governance Profile.
    /// Rejects with the named unmet startup prerequisite first; once startup
    /// is complete the profile ceiling alone decides.
    ///
    /// # Errors
    ///
    /// Returns the blocking [`StartupRejection`] or a profile-ceiling
    /// rejection when the profile does not permit Material authority.
    ///
    /// Production Material/Critical effects never mint a profile for this
    /// check. They bind the recorded Governor-issued projection through
    /// [`KernelComposition::admit_material_authority_for_governor_issued_fence`](super::KernelComposition::admit_material_authority_for_governor_issued_fence),
    /// which admits only the current Governor derivation revision (a newer
    /// degraded revision revokes everything issued under the old one); the
    /// dynamic Watchdog-coverage half is
    /// [`KernelComposition::admit_material_authority_for_fence`](super::KernelComposition::admit_material_authority_for_fence).
    /// This remains the startup-prerequisite and profile-ceiling check,
    /// covered by the unit tests below. Test-only: production
    /// Material/Critical effects never mint a profile (see above), and the
    /// removed `KernelComposition::admit_material_authority` was its last
    /// production caller (#1935 AUD1).
    #[cfg(test)]
    pub(crate) fn admit_material_authority(
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

    /// Records the live Governor-owned derivation projection (I7.16, #1935
    /// AUD1).
    ///
    /// Designated producer: the authenticated `publish_governor_authority`
    /// daemon operation projecting the owner's exact revision, fingerprint,
    /// and authorization axes across the boundary; until it records, every
    /// Material/Critical gate refuses. The revision must
    /// start at one and strictly advance: replaying the current or an older
    /// revision is rejected, so revoked authority can never be resurrected
    /// by re-presenting superseded bytes. Recording a degraded profile
    /// under a new revision revokes everything issued under the old one.
    ///
    /// # Errors
    ///
    /// Returns the fixed-shape reason when the revision is zero or not
    /// strictly newer than the recorded one, or when the fingerprint does
    /// not name the exact active fingerprint.
    pub(crate) fn record_governor_derived_authority(
        &mut self,
        revision: u64,
        fingerprint: String,
        profile: GovernanceProfile,
    ) -> Result<(), String> {
        if revision == 0 {
            return Err("governor authority revision must start at one".to_owned());
        }
        validate_governor_fingerprint(&fingerprint)?;
        if let Some(current) = self.governor_authority.as_ref()
            && revision <= current.revision
        {
            return Err(format!(
                "governor authority revision {revision} does not advance the recorded revision {}",
                current.revision,
            ));
        }
        self.governor_authority = Some(GovernorIssuedAuthority {
            revision,
            fingerprint,
            profile,
        });
        Ok(())
    }

    /// Records Governor-observed coverage loss (I7.16 blind interval / route
    /// mismatch, #1935 AUD1).
    ///
    /// Mirrors the owner's mismatch derivation: the new revision authorizes
    /// nothing ([`GovernanceProfile::minimal`]), so admissions issued under
    /// any older revision are stale and every new Material/Critical request
    /// fails the profile ceiling until the Governor derives again. Same
    /// designated producer and same revision/fingerprint validation as
    /// [`Self::record_governor_derived_authority`].
    ///
    /// # Errors
    ///
    /// Returns the fixed-shape reason when the revision is zero or not
    /// strictly newer than the recorded one, or when the fingerprint does
    /// not name the exact active fingerprint.
    pub(crate) fn report_governor_coverage_loss(
        &mut self,
        revision: u64,
        fingerprint: String,
    ) -> Result<(), String> {
        self.record_governor_derived_authority(revision, fingerprint, GovernanceProfile::minimal())
    }

    /// Current Governor-issued authority projection, if the Governor
    /// derivation has been recorded. `None` fails every Material/Critical
    /// gate closed; it is never defaulted to a strong profile.
    #[must_use]
    pub(crate) fn current_governor_issued_authority(&self) -> Option<GovernorIssuedAuthority> {
        self.governor_authority.clone()
    }

    /// Binds presented Governor-issued authority to the current revision
    /// (I7.16, #1935 AUD1).
    ///
    /// Fails when nothing has been derived, when the presented
    /// revision/fingerprint is not exactly the current one (superseded by a
    /// newer derivation, degraded or not), and returns the currently
    /// authorized profile otherwise. A degraded re-derivation therefore
    /// rejects every capability issued under the lost revision.
    ///
    /// # Errors
    ///
    /// Returns the blocking [`StartupRejection`] when no derivation is
    /// current, or a revision-binding rejection when the presented
    /// authority is stale.
    pub(crate) fn admit_governor_issued_authority(
        &self,
        issued: &GovernorIssuedAuthority,
    ) -> Result<GovernanceProfile, StartupRejection> {
        let Some(current) = self.governor_authority.as_ref() else {
            return Err(StartupRejection {
                prerequisite: StartupPrerequisite::SupervisionEvidence,
                message: "material authority rejected: no Governor-derived coverage profile is current; Material/Critical work is paused until the Governor derivation is recorded".to_owned(),
            });
        };
        if issued.revision != current.revision || issued.fingerprint != current.fingerprint {
            return Err(StartupRejection {
                prerequisite: StartupPrerequisite::SupervisionEvidence,
                message: format!(
                    "material authority rejected: issued governor authority (revision {}, fingerprint '{}') is not the current revision {} for fingerprint '{}'",
                    issued.revision, issued.fingerprint, current.revision, current.fingerprint,
                ),
            });
        }
        Ok(current.profile())
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

    #[cfg(test)]
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

    fn record_step_evidence(&mut self, step: u8) -> Result<(), String> {
        if !(STARTUP_FIRST_STEP..=STARTUP_FINAL_STEP).contains(&step) {
            return Err(format!("startup step {step} is outside I1.11 steps 1-11"));
        }
        self.observed_steps |= 1_u16 << step;
        match step {
            3 => self.epoch_recovered = true,
            5 => self.store_schema_probed = true,
            6 => self.ors_reconciled = true,
            11 => self.supervision_evidence_complete = true,
            _ => {}
        }
        while self.completed_step < STARTUP_FINAL_STEP
            && self.observed_steps & (1_u16 << (self.completed_step + 1)) != 0
        {
            self.completed_step += 1;
        }
        Ok(())
    }

    #[cfg(test)]
    fn complete_ordered(&mut self, step: u8) -> Result<(), String> {
        self.require_next(step)?;
        self.record_step_evidence(step)
    }

    /// Completes one I1.11 step in order, setting the mandatory gate that
    /// step proves. Steps without a mandatory gate only advance the ordered
    /// cursor. Out-of-order or out-of-range steps fail closed.
    ///
    /// # Errors
    ///
    /// Returns a fixed-shape ordering error when `step` is not exactly the
    /// next expected step or lies outside 1-11.
    #[cfg(test)]
    pub(crate) fn complete_step(&mut self, step: u8) -> Result<(), String> {
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

    /// Records evidence produced by a live owner without claiming any missing
    /// earlier step. The contiguous cursor advances only after every gap is
    /// separately observed; repeated probe publication is idempotent.
    ///
    /// # Errors
    ///
    /// Returns the fixed-shape range error when `step` lies outside I1.11.
    pub(crate) fn record_live_evidence(&mut self, step: u8) -> Result<(), String> {
        self.record_step_evidence(step)
    }

    /// True when the I1.11 supervision step has been produced for the current
    /// activation contour.
    ///
    /// I1.5 (#1750): this is the revocable, owner-correct record of one
    /// Host-observed Watchdog branch. It is deliberately not a latched
    /// success: [`Self::revoke_supervision_evidence`] clears it whenever a new
    /// activation contour is admitted, and a contradicted observation clears it
    /// too, so a generation must be observed again before Material/Critical
    /// work is admitted as independently supervised. Currency of the retained
    /// observation is a separate fact, decided by
    /// [`Self::admit_supervision_observation`].
    #[must_use]
    pub const fn supervision_evidence_is_complete(&self) -> bool {
        self.completed_step >= STARTUP_FINAL_STEP && self.supervision_evidence_complete
    }

    /// Requires the recorded independent Watchdog observation to still describe
    /// exactly this candidate contour and exactly this consumer State Fence, and
    /// to still be inside the finite validity interval its own observation time
    /// opens. Returns the Watchdog epoch the observation was taken under, so a
    /// caller joins the lease it is verifying to the observation itself instead
    /// of to a retained string.
    ///
    /// I1.5 (#1750): this is the one freshness and binding gate behind both
    /// dependent decisions — supervised readiness and Material/Critical
    /// admission. A missing, contradicted, contour-foreign, fence-foreign or
    /// expired observation refuses those two and nothing else: normal-write,
    /// inspection and low-impact admission never consult it, and a refusal is
    /// never reported as success. A renewed signed lease advances neither the
    /// observation time nor the progress frontier, so it cannot make an absent
    /// observation current.
    ///
    /// # Errors
    ///
    /// Returns a fixed-shape reason naming the exact observation fact that no
    /// longer holds.
    pub fn admit_supervision_observation(
        &self,
        candidate_digest: &str,
        target: &StateFence,
        now_ms: u64,
    ) -> Result<SupervisionJournalEpoch, &'static str> {
        if !self.supervision_evidence_is_complete() {
            return Err("no Host-observed Watchdog branch for the current contour");
        }
        let current = self
            .current_supervision_observation
            .as_ref()
            .ok_or("no independent Watchdog observation is recorded for the current contour")?;
        if current.candidate_digest.as_str() != candidate_digest {
            return Err(
                "the recorded Watchdog observation belongs to a different candidate contour",
            );
        }
        if !eliot_contracts::fences_match_exact(&current.state_fence, target) {
            return Err(
                "the recorded Watchdog observation belongs to a different consumer State Fence",
            );
        }
        if now_ms.saturating_sub(current.observed_at_ms) > current.valid_for_ms {
            return Err(
                "the recorded Watchdog observation is outside its finite validity interval",
            );
        }
        Ok(current.watchdog_epoch.clone())
    }

    /// Records the I1.11 supervision step together with the independent
    /// Watchdog observation that produced it, bound to the exact contour and
    /// consumer fence it was observed under.
    ///
    /// This is the sole production producer of the supervision claim and the
    /// only writer of the progress frontier. The caller must have just accepted
    /// an owner observation for the presented contour; the carrier's closed
    /// shape is proven here, once, where the record is created, so no consumer
    /// ever decides supervision from re-parsed retained text.
    ///
    /// Re-observing the same incarnation is progress: the record is replaced in
    /// place, its observation time and frontier advance, and the retained
    /// superseded fact is left untouched. Observing a different incarnation
    /// under the same contour and fence contradicts the standing claim: both
    /// facts are retained, the claim is withdrawn, and the caller is told, so
    /// dependent supervision and Material admission narrow until the owner
    /// observes again. The contiguous I1.11 cursor is never rolled back, so no
    /// earlier step is un-observed.
    ///
    /// # Errors
    ///
    /// Returns the fixed-shape range error when the supervision step lies
    /// outside I1.11, when the validity interval is zero, when the carrier is
    /// not in the closed observation shape, or when the observation contradicts
    /// the recorded one.
    pub(crate) fn record_live_supervision_evidence(
        &mut self,
        incarnation: PlatformHandle,
        candidate_digest: PlatformHandle,
        state_fence: StateFence,
        watchdog_epoch: SupervisionJournalEpoch,
        observed_at_ms: u64,
        valid_for_ms: u64,
    ) -> Result<(), String> {
        if valid_for_ms == 0 {
            return Err(
                "a Watchdog supervision observation needs a non-zero validity interval".to_owned(),
            );
        }
        crate::verify_scm_watchdog_observation_shape(&incarnation).map_err(str::to_owned)?;
        let contradicts_recorded = self
            .current_supervision_observation
            .as_ref()
            .is_some_and(|current| current.incarnation != incarnation);
        if contradicts_recorded {
            self.superseded_supervision_observation = self.current_supervision_observation.take();
            self.supervision_evidence_complete = false;
            return Err(
                "a different Watchdog incarnation was observed for the same contour and fence; the contradicted observation is retained and the supervision claim is withdrawn until the owner observes again"
                    .to_owned(),
            );
        }
        self.record_step_evidence(STARTUP_FINAL_STEP)?;
        self.supervision_evidence_complete = true;
        self.supervision_progress_frontier = self.supervision_progress_frontier.saturating_add(1);
        self.current_supervision_observation = Some(WatchdogSupervisionObservation {
            incarnation,
            candidate_digest,
            state_fence,
            watchdog_epoch,
            observed_at_ms,
            progress_frontier: self.supervision_progress_frontier,
            valid_for_ms,
        });
        Ok(())
    }

    /// Revokes the recorded independent-supervision evidence.
    ///
    /// The contiguous cursor is left untouched so no earlier I1.11 step is
    /// un-observed; only the supervision claim itself is withdrawn, and the
    /// observation that produced it is retained as history rather than dropped.
    /// The progress frontier is deliberately not reset: it counts independent
    /// physical observations accepted by this Kernel, not observations of one
    /// contour. Callers use this at the one owner-correct moment a new
    /// candidate contour is admitted (I1.5), because the previous observation
    /// belonged to the previous activation.
    pub fn revoke_supervision_evidence(&mut self) {
        self.supervision_evidence_complete = false;
        if let Some(previous) = self.current_supervision_observation.take() {
            self.superseded_supervision_observation = Some(previous);
        }
        // I7.16 (#1935 AUD1): admitting a new contour supersedes the recorded
        // Governor derivation with it. The old revision's fingerprint binding
        // no longer describes the live contour, so record coverage loss under
        // the next revision (authorizing nothing) until the Governor derives
        // again. On the unreachable validation failure the record is dropped
        // instead, which fails Material/Critical closed either way.
        if let Some(recorded) = self.current_governor_issued_authority() {
            let next = recorded.revision().saturating_add(1).max(1);
            if self
                .report_governor_coverage_loss(next, recorded.fingerprint().to_owned())
                .is_err()
            {
                self.governor_authority = None;
            }
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
    #[cfg(test)]
    pub(crate) fn complete_all_mandatory(&mut self) -> Result<(), String> {
        for step in STARTUP_FIRST_STEP..=STARTUP_FINAL_STEP {
            self.complete_step(step)?;
        }
        Ok(())
    }
}

/// Material/Critical authority admission under the live Governor-owned
/// derivation (I7.16, #1935 AUD1).
///
/// This is the single production gate behind every Material/Critical
/// effect: it reads the current owner-issued revision/fingerprint/profile
/// readback, binds the presented authority to that exact revision, runs
/// the unchanged fence, ceiling and Watchdog-supervision decision, then
/// re-checks revision currency before admitting. A Governor re-derivation
/// (degraded or route-mismatched) that lands mid-admission fails the
/// request closed instead of admitting under a superseded profile, and any
/// authority issued under an older revision is rejected as stale. No
/// hard-coded [`GovernanceProfile::full`] reaches an effect through here.
impl super::KernelComposition {
    /// Admits one Material/Critical effect for one exact target fence under
    /// the current Governor-issued authority.
    ///
    /// # Errors
    ///
    /// Returns a platform error when no Governor derivation is recorded,
    /// when the recorded derivation was superseded mid-admission, or when
    /// the underlying fence, ceiling, or Watchdog-supervision decision
    /// refuses.
    pub(crate) fn admit_material_authority_for_governor_issued_fence(
        &self,
        target: &eliot_contracts::StateFence,
    ) -> Result<(), eliot_kernel_service::KernelServiceError> {
        let lock_poisoned = || {
            eliot_kernel_service::KernelServiceError::Platform(
                "startup gate lock poisoned".to_owned(),
            )
        };
        let issued = self
            .startup_coordinator
            .lock()
            .map_err(|_| lock_poisoned())?
            .current_governor_issued_authority()
            .ok_or_else(|| {
                eliot_kernel_service::KernelServiceError::Platform(
                    "material authority refused: no Governor-derived coverage profile is current for this Kernel"
                        .to_owned(),
                )
            })?;
        let bound = self
            .startup_coordinator
            .lock()
            .map_err(|_| lock_poisoned())?
            .admit_governor_issued_authority(&issued)
            .map_err(|rejection| {
                eliot_kernel_service::KernelServiceError::Platform(rejection.to_string())
            })?;
        self.admit_material_authority_for_fence(bound, target)?;
        let current = self
            .startup_coordinator
            .lock()
            .map_err(|_| lock_poisoned())?
            .current_governor_issued_authority();
        if current.as_ref().is_none_or(|fresh| {
            fresh.revision() != issued.revision() || fresh.fingerprint() != issued.fingerprint()
        }) {
            return Err(eliot_kernel_service::KernelServiceError::Platform(
                "material authority refused: the Governor derivation advanced during admission; re-present under the current revision".to_owned(),
            ));
        }
        Ok(())
    }

    /// Records one Governor-issued coverage projection published across the
    /// authenticated daemon boundary (I7.16, #1935 AUD1).
    ///
    /// Designated producer: the `publish_governor_authority` daemon operation.
    /// The owner revision, exact active fingerprint, and exact authorization
    /// axes arrive in the owner's own vocabulary (no third profile is
    /// introduced); the axes map to this crate's existing three-axis
    /// [`GovernanceProfile`] and record under the existing strictly-advancing
    /// revision rule, so a newer degraded projection revokes everything
    /// issued under the old one.
    ///
    /// # Errors
    ///
    /// Returns a platform error when the startup gate lock is poisoned, and
    /// the fixed-shape reason when the revision does not strictly advance or
    /// the fingerprint does not name the exact active fingerprint.
    pub(crate) fn record_governor_issued_coverage_projection(
        &self,
        revision: u64,
        fingerprint: String,
        verified: bool,
        authorizes_enforcement: bool,
        authorizes_complete_coverage_ops: bool,
    ) -> Result<(), eliot_kernel_service::KernelServiceError> {
        let profile = governor_authorization_axes_to_profile(
            verified,
            authorizes_enforcement,
            authorizes_complete_coverage_ops,
        );
        let mut coordinator = self.startup_coordinator.lock().map_err(|_| {
            eliot_kernel_service::KernelServiceError::Platform(
                "startup gate lock poisoned".to_owned(),
            )
        })?;
        coordinator
            .record_governor_derived_authority(revision, fingerprint, profile)
            .map_err(eliot_kernel_service::KernelServiceError::Platform)
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
    fn incomplete_startup_rejects_write_and_material_and_inspection() {
        let coordinator = coordinator_at_step(4);
        assert!(!coordinator.admit_inspection());
        let write = coordinator
            .admit_normal_write()
            .expect_err("normal write must fail before step 5");
        assert_eq!(
            write.prerequisite_name(),
            "store-schema-probe",
            "rejection must name the unmet prerequisite, got: {write}",
        );
        let material = coordinator
            .admit_material_authority(GovernanceProfile::full())
            .expect_err("material must fail before step 5");
        assert_eq!(material.prerequisite_name(), "store-schema-probe");
        let status = coordinator.startup_status(GovernanceProfile::full());
        assert_eq!(status.completed_step, 4);
        assert_eq!(
            status.blocking_prerequisite,
            Some("store-schema-probe"),
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
            StartupPrerequisite::EpochRecovery,
            StartupPrerequisite::StoreSchemaProbe,
            StartupPrerequisite::OrsReconciliation,
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
        assert!(full.admit_inspection());
        let _ = &mut full;
    }

    #[test]
    fn live_evidence_keeps_unobserved_startup_gaps_blocking() {
        let mut coordinator = StartupCoordinator::new();
        coordinator
            .record_live_evidence(3)
            .expect("epoch recovery evidence");
        assert_eq!(coordinator.completed_step(), 0);
        assert_eq!(
            coordinator.blocking_prerequisite(),
            Some(StartupPrerequisite::EpochRecovery)
        );

        coordinator
            .record_live_evidence(5)
            .expect("store schema evidence");
        coordinator
            .record_live_evidence(10)
            .expect("front-door publication evidence");
        assert_eq!(coordinator.completed_step(), 0);
        assert_eq!(
            coordinator.blocking_prerequisite(),
            Some(StartupPrerequisite::EpochRecovery)
        );
        assert!(!coordinator.admit_inspection());
    }

    #[test]
    fn out_of_order_gate_evidence_cannot_bypass_the_contiguous_cursor() {
        let mut coordinator = StartupCoordinator::new();
        for step in [3, 5, 6, 8, 9, 10, 11] {
            coordinator
                .record_live_evidence(step)
                .expect("in-range live evidence");
        }

        assert_eq!(coordinator.completed_step(), 0);
        assert_eq!(
            coordinator.blocking_prerequisite(),
            Some(StartupPrerequisite::EpochRecovery)
        );
        assert!(coordinator.admit_normal_write().is_err());
        assert!(!coordinator.admit_inspection());

        coordinator
            .record_live_evidence(1)
            .expect("host validation evidence");
        assert_eq!(coordinator.completed_step(), 1);
        assert_eq!(
            coordinator.blocking_prerequisite(),
            Some(StartupPrerequisite::EpochRecovery)
        );

        coordinator
            .record_live_evidence(2)
            .expect("kernel start evidence");
        assert_eq!(coordinator.completed_step(), 3);
        assert_eq!(
            coordinator.blocking_prerequisite(),
            Some(StartupPrerequisite::StoreSchemaProbe)
        );
        assert!(coordinator.admit_normal_write().is_err());
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
