//! Read-only installation-chain and hook-health observation for the
//! independent Watchdog.
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose),
//! ARCH-WDG-01, A13.2.
//! Implementation: I8.1, I8.2, I8.5
//! (docs/architecture/I08-05-hookplugin-health.md#i85-hookplugin-health),
//! I3.7 (docs/architecture/I03-07-plugin-registration.md#i37-plugin-registration),
//! I7.16
//! (docs/architecture/I07-16-host-integration-coverage-and-governance-profile.md#i716-host-integration-coverage-and-governance-profile).
//!
//! `installed = true` is not `healthy = true`. This cell compares one semantic
//! installation chain stage by stage and derives the health verdict from the
//! owners that actually recorded each stage. It never infers installation from
//! an existing directory, a matching configuration file, or a hash the caller
//! supplied, and it never compares a source template byte-for-byte with
//! generated configuration: adjacent stages are related only through the
//! transformation the receiving owner declared.
//!
//! Scope and privacy: the single path read is the installer-approved
//! `ServiceBootstrapArguments` this Watchdog process's own SCM registration
//! carried, under the retained no-follow Host-state root lease. No credential,
//! private tool data, or user content is read, and no recorded path or digest is
//! emitted to a log. This cell performs no configuration mutation, install,
//! deletion, disable, or repair, and it mints no coverage authority: the
//! ten-event readback it hands to the Governor integration-coverage adapter is
//! exactly as complete as the readbacks its owners retained.

use std::path::Path;

use eliot_installation::{
    ActivePhaseBRebindReceipt, CandidateManifest, InstallationError, phase_b_scm_selector,
};
use eliot_integration_coverage::{
    ALL_EVENTS, CoverageError, LiveCoverageObservation, LiveCoverageReadback, LiveEventReadback,
};
use eliot_platform_windows::{ServiceBootstrapArguments, windows_paths_equal};
use thiserror::Error;

use crate::host_identity_observation::read_host_registration_runtime;
use crate::runtime_manifest_selection::read_registry_for_bootstrap;
use crate::service_registration_projection::load_approved_service_registrations;

/// The exact owner whose readback failed, retained with its own typed source so
/// no layer's failure collapses into a string or a generic code.
#[derive(Debug, Error)]
pub enum ChainOwnerError {
    #[error(transparent)]
    InstallationRegistry(crate::SpoolError),
    #[error(transparent)]
    ServiceRegistrationApproval(crate::SpoolError),
    #[error(transparent)]
    PhaseBRebindReceipt(InstallationError),
}

/// Typed installation-chain readback failures.
#[derive(Debug, Error)]
pub enum ChainError {
    #[error("installation-chain owner is unavailable: {0}")]
    OwnerUnavailable(&'static str, #[source] ChainOwnerError),
    #[error("chain stage set is not the complete expected set: {0}")]
    IncompleteStageSet(&'static str),
    #[error("declared transformation does not join the adjacent chain stages: {0}")]
    UndeclaredTransformation(&'static str),
    #[error("chain member identity is invalid: {0}")]
    InvalidMember(String),
}

/// The nine installation-chain stages this contour binds, in the order the
/// semantic chain is declared. The ninth stage — the live event readback — is
/// typed separately as [`LiveEventReadbackSet`] because it is a per-event
/// observation set rather than one recorded identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ChainStage {
    /// Tracked source version of the approved generation.
    TrackedSourceVersion,
    /// Declared generator/configuration/schema revision.
    GeneratorConfigurationRevision,
    /// Digest of the generated artifact set actually published.
    GeneratedArtifactDigest,
    /// Installer receipt identity for this publication.
    InstallerReceipt,
    /// Identity of the paths the installer published into.
    InstalledPathIdentity,
    /// Live observation of the active registration, not a configuration copy.
    ActiveRegistration,
    /// Bridge/executable identity of the admitted integration.
    BridgeExecutableIdentity,
    /// Installer-approved runtime/adapter identity for this Watchdog.
    RuntimeAdapterFingerprint,
    /// Retained live readback of the event path.
    LiveEventReadback,
}

/// The complete expected stage set in canonical order.
pub const CHAIN_STAGES: [ChainStage; 9] = [
    ChainStage::TrackedSourceVersion,
    ChainStage::GeneratorConfigurationRevision,
    ChainStage::GeneratedArtifactDigest,
    ChainStage::InstallerReceipt,
    ChainStage::InstalledPathIdentity,
    ChainStage::ActiveRegistration,
    ChainStage::BridgeExecutableIdentity,
    ChainStage::RuntimeAdapterFingerprint,
    ChainStage::LiveEventReadback,
];

/// Why a chain stage carries no recorded value. Presence is never inferred from
/// an existing directory, a matching configuration file, or a hash the caller
/// supplied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainAbsence {
    /// No admitted owner records this step for this contour.
    OwnerNotAdmitted,
    /// The installer recorded no receipt for this step.
    ReceiptMissing,
    /// No supported runtime registration observation exists.
    RegistrationUnobservable,
    /// The step is installed, but the live event path was not read back.
    LiveEventNotRead,
}

impl ChainAbsence {
    /// Stable diagnostic name. Every absence keeps a distinct name so a gap is
    /// never reported as a version, path, or readback mismatch.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerNotAdmitted => "owner_not_admitted",
            Self::ReceiptMissing => "receipt_missing",
            Self::RegistrationUnobservable => "registration_unobservable",
            Self::LiveEventNotRead => "live_event_not_read",
        }
    }
}

/// One chain stage bound to exactly what its owner recorded, or to the explicit
/// reason it recorded nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainStageBinding {
    stage: ChainStage,
    value: Option<String>,
    absence: Option<ChainAbsence>,
}

impl ChainStageBinding {
    fn recorded(stage: ChainStage, value: impl Into<String>) -> Self {
        Self {
            stage,
            value: Some(value.into()),
            absence: None,
        }
    }

    fn absent(stage: ChainStage, absence: ChainAbsence) -> Self {
        Self {
            stage,
            value: None,
            absence: Some(absence),
        }
    }

    /// Returns the value this stage's owner recorded, if it recorded one.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Returns the explicit reason this stage has no recorded value.
    #[must_use]
    pub fn absence(&self) -> Option<ChainAbsence> {
        self.absence
    }
}

/// The transformation one chain owner declared between two adjacent stages.
///
/// The chain compares this declaration, never the bytes of the two stages: a
/// generator may legitimately render different configuration bytes for the
/// same tracked source, so a source template and a generated file are never
/// required to be byte-equal and neither stage value is compared with the
/// other.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredTransformation {
    /// Stage the transformation reads.
    pub from: ChainStage,
    /// Stage the transformation writes.
    pub to: ChainStage,
    /// Identity of the transformation the receiving owner declared.
    pub kind: String,
    /// Owner-recorded revision of that transformation.
    pub revision: String,
}

/// One member of the integration's member set: an installed hook, an active
/// registration, or an exposed tool/Skill.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ChainMember {
    pub member_id: String,
    /// Original Windows SCM registry key that owns this service identity.
    pub registry_owner: String,
    /// Interception/endpoint ownership this member claims. Two observed
    /// members claiming one ownership are competing registrations, not two
    /// legitimate independent applications.
    pub ownership_claim: String,
    /// Exact SCM command recorded by the service owner.
    pub registration_config: String,
    /// Identity this member actually presented.
    pub identity: String,
}

impl ChainMember {
    fn new(
        member_id: impl Into<String>,
        ownership_claim: impl Into<String>,
        registration_config: impl Into<String>,
        identity: impl Into<String>,
    ) -> Result<Self, ChainError> {
        let member_id = member_id.into();
        let member = Self {
            registry_owner: format!(
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{}",
                member_id
            ),
            member_id,
            ownership_claim: ownership_claim.into(),
            registration_config: registration_config.into(),
            identity: identity.into(),
        };
        if member.member_id.trim().is_empty()
            || member.registry_owner.trim().is_empty()
            || member.ownership_claim.trim().is_empty()
            || member.registration_config.trim().is_empty()
            || member.identity.trim().is_empty()
        {
            return Err(ChainError::InvalidMember(member.member_id));
        }
        Ok(member)
    }
}

/// Competing observed members claiming one interception/endpoint ownership.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ConflictingOwnership {
    pub ownership_claim: String,
    pub members: Vec<ChainMember>,
}

/// The complete expected member set reconciled against what the owner observed.
///
/// `scope_enumerated` is the honest bound on these lists: when it is `false`,
/// no admitted owner enumerates the whole scope, so extra members are
/// unobservable and an empty `observed` list proves nothing about them. An
/// absent enumeration is never reported as "no extra members".
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct MemberReconciliation {
    pub expected: Vec<ChainMember>,
    pub observed: Vec<ChainMember>,
    pub missing: Vec<ChainMember>,
    pub extra: Vec<ChainMember>,
    pub conflicting: Vec<ConflictingOwnership>,
    /// Bounded owner-enumeration gaps with only service identity and Win32
    /// error codes; an incomplete inventory never masquerades as no extras.
    pub inventory_gaps: Vec<String>,
    pub scope_enumerated: bool,
}

/// The live event readback the chain's owners actually retained for this
/// operation.
///
/// Every entry is recorded by the owner that performed the readback. An empty
/// set is an explicit absence, never an implied observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveEventReadbackSet {
    /// Identity of the owner that performed these readbacks.
    pub owner: String,
    /// Per-event observations actually retained.
    pub events: Vec<LiveEventReadback>,
}

impl LiveEventReadbackSet {
    /// Returns whether this owner retained a readback for every logical event.
    #[must_use]
    pub fn covers_all_events(&self) -> bool {
        ALL_EVENTS
            .iter()
            .all(|event| self.events.iter().any(|row| row.event == *event))
    }

    /// Derives the ten-event readback the Governor adapter consumes for this
    /// exact operation.
    ///
    /// This is the only producer of a [`LiveCoverageReadback`] in this
    /// composition: the value that reaches
    /// `IntegrationCoverageProfile::verify` is derived from the owner's
    /// recorded set, and a missing, partial, or unreadable set is refused
    /// instead of being defaulted to observed.
    pub fn coverage_readback(
        &self,
        active_fingerprint: &str,
    ) -> Result<LiveCoverageReadback, CoverageError> {
        LiveCoverageReadback::recorded(
            self.owner.clone(),
            active_fingerprint,
            self.events.iter().cloned(),
        )
    }
}

/// Health of one semantic installation chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainHealth {
    /// Installed and digest-bound, with no complete live readback of the event
    /// path. A matching configuration file without a live event path is this
    /// state, never healthy.
    InstalledUnobserved,
    /// Competing members claim one interception/endpoint ownership.
    Conflicting,
    /// Every stage recorded, the complete expected member set enumerated, and a
    /// complete live readback retained.
    Observed,
}

impl ChainHealth {
    /// Stable diagnostic name. Every variant maps to a distinct string and
    /// `installed_unobserved` never collapses into `observed`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstalledUnobserved => "installed_unobserved",
            Self::Conflicting => "conflicting",
            Self::Observed => "observed",
        }
    }
}

/// One bound installation chain: the complete stage set, the declared
/// transformation between each adjacent pair, the member reconciliation, the
/// live readback, and the health verdict derived from all of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationChain {
    /// Registered installation/user scope this chain was read from.
    pub scope: String,
    stages: Vec<ChainStageBinding>,
    links: Vec<DeclaredTransformation>,
    pub members: MemberReconciliation,
    pub live_readback: LiveEventReadbackSet,
    pub health: ChainHealth,
    /// Installer-issued installation identity whose scope was enumerated.
    pub installation_id: String,
    /// Watchdog source generation selected by the retained manifest.
    pub source_generation: u64,
    /// Authority epoch sequence from that same manifest.
    pub authority_epoch: u64,
    /// Owner clock at the end of the complete SCM/chain read.
    pub observed_at_ms: u64,
    /// Full serialized StateFence read from the selected manifest.
    pub state_fence_json: String,
}

/// Original retained SCM registration observation and its independent expected
/// set, bound to the exact source generation, owner clock and authority fence.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct HookChainObservation {
    pub source_observation_id: String,
    pub installation_id: String,
    pub scope: String,
    pub source_generation: u64,
    pub authority_epoch: u64,
    pub observed_at_ms: u64,
    pub state_fence_json: String,
    /// Actual closed I8.2 per-channel interval emitted by the Watchdog sensor
    /// in this tick. Every fixed-map channel, competent source, class, and gap
    /// is retained; missing adapters remain gaps in the denominator.
    pub interval_coverage: Option<serde_json::Value>,
    pub health: ChainHealth,
    pub members: MemberReconciliation,
}

impl IntegrationChain {
    /// Assembles the chain from the values its owners recorded.
    ///
    /// The ninth stage binding and the health verdict are derived here, never
    /// supplied: a caller cannot present a chain as healthy, and the verdict
    /// follows the evidence rather than a claim about it.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::IncompleteStageSet`] unless the first eight
    /// stages are exactly [`CHAIN_STAGES`] in order with one recorded value or
    /// one explicit absence each, and
    /// [`ChainError::UndeclaredTransformation`] unless every adjacent pair is
    /// joined by exactly one declared transformation the receiving owner
    /// recorded.
    pub fn assemble(
        scope: impl Into<String>,
        stages: Vec<ChainStageBinding>,
        links: Vec<DeclaredTransformation>,
        expected: Vec<ChainMember>,
        observed: Vec<ChainMember>,
        inventory_gaps: Vec<String>,
        scope_enumerated: bool,
        live_readback: LiveEventReadbackSet,
    ) -> Result<Self, ChainError> {
        let stages = with_live_readback_stage(stages, &live_readback);
        validate_stage_set(&stages)?;
        validate_links(&links)?;
        let members = reconcile_members(expected, observed, inventory_gaps, scope_enumerated);
        let health = if !members.conflicting.is_empty() {
            ChainHealth::Conflicting
        } else if stages.iter().any(|stage| stage.value.is_none())
            || !members.missing.is_empty()
            || !members.extra.is_empty()
            || !scope_enumerated
            || !live_readback.covers_all_events()
        {
            ChainHealth::InstalledUnobserved
        } else {
            ChainHealth::Observed
        };
        Ok(Self {
            scope: scope.into(),
            stages,
            links,
            members,
            live_readback,
            health,
            installation_id: String::new(),
            source_generation: 0,
            authority_epoch: 0,
            observed_at_ms: 0,
            state_fence_json: String::new(),
        })
    }

    /// Returns the value one stage's owner recorded, if it recorded one.
    #[must_use]
    pub fn stage(&self, stage: ChainStage) -> Option<&str> {
        self.stages
            .iter()
            .find(|binding| binding.stage == stage)
            .and_then(ChainStageBinding::value)
    }

    /// Returns the explicit absence recorded for one stage, if any.
    #[must_use]
    pub fn stage_absence(&self, stage: ChainStage) -> Option<ChainAbsence> {
        self.stages
            .iter()
            .find(|binding| binding.stage == stage)
            .and_then(ChainStageBinding::absence)
    }

    /// Returns the declared transformation the receiving owner recorded for one
    /// stage.
    #[must_use]
    pub fn transformation(&self, to: ChainStage) -> Option<&DeclaredTransformation> {
        self.links.iter().find(|link| link.to == to)
    }
}

fn with_live_readback_stage(
    mut stages: Vec<ChainStageBinding>,
    live_readback: &LiveEventReadbackSet,
) -> Vec<ChainStageBinding> {
    stages.push(if live_readback.covers_all_events() {
        ChainStageBinding::recorded(ChainStage::LiveEventReadback, live_readback.owner.clone())
    } else {
        ChainStageBinding::absent(
            ChainStage::LiveEventReadback,
            ChainAbsence::LiveEventNotRead,
        )
    });
    stages
}

fn validate_stage_set(stages: &[ChainStageBinding]) -> Result<(), ChainError> {
    if stages.len() != CHAIN_STAGES.len() {
        return Err(ChainError::IncompleteStageSet("stage_count"));
    }
    for (index, required) in CHAIN_STAGES.iter().enumerate() {
        let binding = stages
            .get(index)
            .ok_or(ChainError::IncompleteStageSet("stage_count"))?;
        if binding.stage != *required {
            return Err(ChainError::IncompleteStageSet("stage_order"));
        }
        if binding.value.is_some() == binding.absence.is_some() {
            return Err(ChainError::IncompleteStageSet("stage_evidence"));
        }
        if let Some(value) = binding.value.as_deref()
            && (value.trim().is_empty() || value.chars().any(char::is_control))
        {
            return Err(ChainError::IncompleteStageSet("stage_value"));
        }
    }
    Ok(())
}

fn validate_links(links: &[DeclaredTransformation]) -> Result<(), ChainError> {
    if links.len() != CHAIN_STAGES.len() - 1 {
        return Err(ChainError::UndeclaredTransformation("link_count"));
    }
    for (index, link) in links.iter().enumerate() {
        if link.from != CHAIN_STAGES[index] || link.to != CHAIN_STAGES[index + 1] {
            return Err(ChainError::UndeclaredTransformation("link_order"));
        }
        if link.kind.trim().is_empty() || link.revision.trim().is_empty() {
            return Err(ChainError::UndeclaredTransformation("link_identity"));
        }
    }
    Ok(())
}

fn reconcile_members(
    expected: Vec<ChainMember>,
    observed: Vec<ChainMember>,
    inventory_gaps: Vec<String>,
    scope_enumerated: bool,
) -> MemberReconciliation {
    let missing: Vec<ChainMember> = expected
        .iter()
        // SCM service names are case-insensitive identifiers. Preserve the
        // original spelling in evidence while joining on the owner's rules.
        .filter(|member| {
            !observed
                .iter()
                .any(|row| row.member_id.eq_ignore_ascii_case(&member.member_id))
        })
        .cloned()
        .collect();
    let extra: Vec<ChainMember> = observed
        .iter()
        .filter(|member| {
            !expected
                .iter()
                .any(|row| row.member_id.eq_ignore_ascii_case(&member.member_id))
        })
        .cloned()
        .collect();
    let mut conflicting: Vec<ConflictingOwnership> = Vec::new();
    // An observed member that presents an identity other than the approved
    // one is a competing registration claiming that interception/endpoint
    // ownership, not the approved member.
    for member in &observed {
        if let Some(approved) = expected
            .iter()
            .find(|row| row.member_id.eq_ignore_ascii_case(&member.member_id))
            && (approved.registration_config != member.registration_config
                || !windows_paths_equal(Path::new(&approved.identity), Path::new(&member.identity)))
        {
            push_conflict(
                &mut conflicting,
                &member.ownership_claim,
                vec![approved.clone(), member.clone()],
            );
        }
    }
    // Independent applications stay independent: only two observed members
    // claiming one ownership with different identities conflict.
    let mut claims: Vec<&str> = observed
        .iter()
        .map(|member| member.ownership_claim.as_str())
        .collect();
    claims.sort_unstable();
    claims.dedup();
    for claim in claims {
        let members: Vec<ChainMember> = observed
            .iter()
            .filter(|member| member.ownership_claim == claim)
            .cloned()
            .collect();
        if members.len() > 1 {
            push_conflict(&mut conflicting, claim, members);
        }
    }
    MemberReconciliation {
        expected,
        observed,
        missing,
        extra,
        conflicting,
        inventory_gaps,
        scope_enumerated,
    }
}

fn push_conflict(
    conflicting: &mut Vec<ConflictingOwnership>,
    ownership_claim: &str,
    members: Vec<ChainMember>,
) {
    if let Some(existing) = conflicting
        .iter_mut()
        .find(|row| row.ownership_claim == ownership_claim)
    {
        for member in members {
            if !existing.members.iter().any(|candidate| {
                candidate.member_id.eq_ignore_ascii_case(&member.member_id)
                    && candidate.registration_config == member.registration_config
                    && candidate.identity.eq_ignore_ascii_case(&member.identity)
            }) {
                existing.members.push(member);
            }
        }
    } else {
        conflicting.push(ConflictingOwnership {
            ownership_claim: ownership_claim.to_owned(),
            members,
        });
    }
}

/// Read-only installation-chain observation for the exact installer-approved
/// registration this Watchdog process was admitted with.
///
/// This type performs no configuration mutation, install, deletion, disable, or
/// repair, and it mints no coverage authority. It is the observing owner for
/// the Governor integration-coverage adapter: only the readback it records can
/// establish production observation.
pub struct LiveHookChainSource {
    bootstrap: ServiceBootstrapArguments,
}

impl LiveHookChainSource {
    /// Binds the source to the installer-approved bootstrap of this process's
    /// own SCM registration. The caller cannot supply a scope, a hash, an
    /// installation path, or an observation verdict.
    #[must_use]
    pub const fn new(bootstrap: ServiceBootstrapArguments) -> Self {
        Self { bootstrap }
    }

    /// Reads the whole chain from its owners and records the bounded health
    /// observation. `installed` is never reported as `healthy`: a chain
    /// without a retained live event readback stays
    /// [`ChainHealth::InstalledUnobserved`].
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::OwnerUnavailable`] when the installer registry,
    /// its service-registration approvals, or its retained Phase-B rebind
    /// receipt cannot be read or validated for this scope. A readable registry
    /// whose owner recorded nothing for one stage is not an error: it is an
    /// explicit [`ChainAbsence`] on that stage, and it keeps the chain
    /// unobserved rather than failing the whole read.
    pub fn observe_chain(&self) -> Result<IntegrationChain, ChainError> {
        let chain = match self.read_chain() {
            Ok(chain) => chain,
            Err(error) => {
                if let ChainError::OwnerUnavailable(owner, source) = &error {
                    tracing::warn!(event = "watchdog.hook_chain_owner_unavailable", owner = *owner, source = ?source, "hook-chain owner readback is unavailable");
                }
                return Err(error);
            }
        };
        tracing::debug!(event = "watchdog.hook_chain_observed", health = chain.health.as_str(), missing = chain.members.missing.len(), extra = chain.members.extra.len(), conflicting = chain.members.conflicting.len(), scope_enumerated = chain.members.scope_enumerated, "hook-chain owner readback completed");
        Ok(chain)
    }

    fn read_chain(&self) -> Result<IntegrationChain, ChainError> {
        let (registry, manifest) =
            read_registry_for_bootstrap(&self.bootstrap).map_err(|error| {
                ChainError::OwnerUnavailable(
                    "installation_registry",
                    ChainOwnerError::InstallationRegistry(error),
                )
            })?;
        let rebind = registry.active_phase_b_rebind();
        if let Some(rebind) = rebind {
            // The original recorded value is validated through its own
            // validator; recomputing a fresh checksum over the fields held here
            // would prove only that this cell can read them.
            rebind.validate().map_err(|error| {
                ChainError::OwnerUnavailable(
                    "phase_b_rebind_receipt",
                    ChainOwnerError::PhaseBRebindReceipt(error),
                )
            })?;
        }
        let receipt = rebind.and_then(|rebind| rebind.receipt.as_ref());
        let (approved_host, approved_watchdog) =
            load_approved_service_registrations(&registry, &manifest, &self.bootstrap).map_err(
                |error| {
                    ChainError::OwnerUnavailable(
                        "service_registration_approval",
                        ChainOwnerError::ServiceRegistrationApproval(error),
                    )
                },
            )?;
        let service_name = approved_host.request.service_name().to_owned();
        let readback = read_host_registration_runtime(&approved_host);
        let expected = vec![
            ChainMember::new(
                approved_host.request.service_name(),
                ownership_claim_for_image(approved_host.request.binary_path()),
                approved_host.request.binary_command_line(),
                approved_host.request.binary_path().display().to_string(),
            )?,
            ChainMember::new(
                approved_watchdog.service_name(),
                ownership_claim_for_image(approved_watchdog.binary_path()),
                approved_watchdog.binary_command_line(),
                approved_watchdog.binary_path().display().to_string(),
            )?,
        ];
        let inventory = eliot_platform_windows::WindowsPlatform::enumerate_active_service_registrations();
        let owner_root = approved_host
            .request
            .binary_path()
            .parent()
            .map(|path| path.to_string_lossy().into_owned());
        let mut scope_enumerated = inventory.complete;
        let mut observed = Vec::new();
        let mut inventory_gaps = Vec::new();
        if let Some(error) = inventory.win32_error {
            inventory_gaps.push(format!("scm_enumeration_win32:{error}"));
        }
        for registration in &inventory.entries {
            let Some(configured_command) = registration.configured_command.as_deref() else {
                // Without the SCM command, this active entry cannot be proven
                // outside this install scope, so extra-member absence remains
                // unobservable for the whole owner inventory.
                scope_enumerated = false;
                let error = registration
                    .configuration_error
                    .map_or_else(|| "unavailable".to_owned(), |code| code.to_string());
                inventory_gaps.push(format!(
                    "service_configuration_unavailable:{}:{error}",
                    registration.service_name
                ));
                continue;
            };
            let belongs_to_install = expected.iter().any(|member| {
                member.member_id.eq_ignore_ascii_case(&registration.service_name)
            }) || service_image_from_command(configured_command).is_some_and(|image| {
                owner_root
                    .as_deref()
                    .is_some_and(|root| image_is_within_install(image, root))
            }) || registration.process.as_ref().is_some_and(|process| {
                owner_root.as_deref().is_some_and(|root| {
                    image_is_within_install(&process.image_path, root)
                })
            });
            if !belongs_to_install {
                continue;
            }
            let Some(process) = registration.process.as_ref() else {
                scope_enumerated = false;
                let error = registration
                    .process_identity_error
                    .map_or_else(|| "unavailable".to_owned(), |code| code.to_string());
                inventory_gaps.push(format!(
                    "service_process_identity_unavailable:{}:{error}",
                    registration.service_name
                ));
                continue;
            };
            let identity_path = Path::new(&process.image_path);
            let member = ChainMember::new(
                registration.service_name.clone(),
                ownership_claim_for_image(identity_path),
                configured_command.to_owned(),
                process.image_path.clone(),
            )?;
            observed.push(member);
        }
        if inventory.win32_error.is_some()
            || inventory.entries.iter().any(|entry| entry.configuration_error.is_some())
        {
            scope_enumerated = false;
        }
        let mut chain = IntegrationChain::assemble(
            self.bootstrap.installation_id().to_owned(),
            chain_stages(&manifest, receipt, &readback, &service_name),
            chain_links(receipt),
            expected,
            observed,
            inventory_gaps,
            scope_enumerated,
            LiveEventReadbackSet {
                owner: "watchdog:hook-chain".to_owned(),
                // The ten logical events have no admitted live readback owner
                // in this contour: this cell reads the installation chain and
                // the active registration, never a host hook event. The empty
                // set is an explicit absence, so the chain is
                // `INSTALLED_UNOBSERVED` rather than healthy.
                events: Vec::new(),
            },
        )?;
        chain.installation_id = manifest
            .runtime_launch
            .installation_epoch
            .installation
            .as_str()
            .to_owned();
        chain.source_generation = manifest
            .runtime_launch
            .authority_generation
            .value();
        chain.authority_epoch = manifest
            .runtime_launch
            .authority_state_fence
            .authority_epoch
            .sequence
            .get();
        chain.observed_at_ms = crate::current_unix_ms().ok_or_else(|| {
            ChainError::InvalidMember("watchdog owner clock is unavailable".to_owned())
        })?;
        chain.state_fence_json = serde_json::to_string(
            &manifest.runtime_launch.authority_state_fence,
        )
        .map_err(|_| ChainError::InvalidMember("recorded StateFence serialization failed".to_owned()))?;
        Ok(chain)
    }
}

impl From<&IntegrationChain> for HookChainObservation {
    fn from(chain: &IntegrationChain) -> Self {
        let observation_material = format!(
            "watchdog-hook-chain-v1\0{}\0{}\0{}\0{}",
            chain.installation_id,
            chain.source_generation,
            chain.authority_epoch,
            chain.observed_at_ms,
        );
        Self {
            source_observation_id: eliot_contracts::sha256_hex(observation_material.as_bytes()),
            installation_id: chain.installation_id.clone(),
            scope: chain.scope.clone(),
            source_generation: chain.source_generation,
            authority_epoch: chain.authority_epoch,
            observed_at_ms: chain.observed_at_ms,
            state_fence_json: chain.state_fence_json.clone(),
            interval_coverage: None,
            health: chain.health,
            members: chain.members.clone(),
        }
    }
}

fn ownership_claim_for_image(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_lowercase()
}

pub(crate) fn project_interval_coverage(
    report: &crate::observation_coverage::IntervalCoverageReport,
) -> serde_json::Value {
    let interval = report.interval();
    let interval_identity = format!(
        "watchdog-interval-v1\0{}\0{}\0{}",
        report.sensor_map_revision(),
        interval.start_ms,
        interval.end_ms,
    );
    let records = report
        .records()
        .iter()
        .map(|record| {
            serde_json::json!({
                "channel": record.channel().as_str(),
                "competent_source": record.expected_source(),
                "competent_classes": record.expected_classes().iter().map(|class| class.as_str()).collect::<Vec<_>>(),
                "observed_classes": record.observed_classes().iter().map(|class| class.as_str()).collect::<Vec<_>>(),
                "replayed_observations": record.observed_replayed_observations(),
                "dropped_samples": record.dropped_samples(),
                "interval_closed": record.interval_closed(),
                "disposition": record.disposition().as_str(),
                "gaps": record.gaps().iter().map(|gap| serde_json::json!({
                    "channel": gap.channel.as_str(),
                    "reason": gap.reason,
                })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "interval_id": eliot_contracts::sha256_hex(interval_identity.as_bytes()),
        "sensor_map_revision": report.sensor_map_revision(),
        "interval": { "start_ms": interval.start_ms, "end_ms": interval.end_ms },
        "valid": report.valid(),
        "full_coverage_claimed": report.full_coverage_claimed(),
        "records": records,
    })
}

fn service_image_from_command(command: &str) -> Option<&str> {
    let command = command.trim_start();
    if let Some(quoted) = command.strip_prefix('"') {
        return quoted.split_once('"').map(|(image, _)| image);
    }
    let executable_end = command.to_ascii_lowercase().find(".exe")? + ".exe".len();
    Some(command.get(..executable_end)?.trim())
}

fn image_is_within_install(image: &str, install_root: &str) -> bool {
    let normalize = |value: &str| {
        value
            .trim_matches('"')
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    };
    let image = normalize(image);
    let root = normalize(install_root);
    image == root || image.strip_prefix(&root).is_some_and(|tail| tail.starts_with('\\'))
}

impl LiveCoverageObservation for LiveHookChainSource {
    fn observe_live_coverage(&self) -> Result<LiveCoverageReadback, CoverageError> {
        let chain = self
            .observe_chain()
            .map_err(|_| CoverageError::LiveReadbackUnavailable("watchdog_hook_chain_owner"))?;
        // The active fingerprint the Governor adapter compares is the
        // runtime/adapter identity this chain bound from the installer's own
        // approval, so a profile built for another runtime cannot match it.
        let fingerprint = chain.stage(ChainStage::RuntimeAdapterFingerprint).ok_or(
            CoverageError::LiveReadbackUnavailable("watchdog_hook_chain_runtime_adapter"),
        )?;
        chain.live_readback.coverage_readback(fingerprint)
    }
}

fn chain_stages(
    manifest: &CandidateManifest,
    receipt: Option<&ActivePhaseBRebindReceipt>,
    readback: &WatchdogRuntimeReadback,
    service_name: &str,
) -> Vec<ChainStageBinding> {
    let launch = &manifest.runtime_launch;
    let bridge = receipt.and_then(|receipt| {
        let binding = receipt.agent_bridge.as_ref()?;
        // Validate the original recorded bridge binding through its own
        // validator before using any identity it carries.
        binding.validate().ok()?;
        Some(binding.staged_destination_path.as_str())
    });
    vec![
        ChainStageBinding::recorded(
            ChainStage::TrackedSourceVersion,
            manifest.generation.as_str(),
        ),
        match phase_b_scm_selector(&launch.authority_descriptor_digest) {
            Ok(revision) => ChainStageBinding::recorded(
                ChainStage::GeneratorConfigurationRevision,
                revision.as_str(),
            ),
            Err(_) => ChainStageBinding::absent(
                ChainStage::GeneratorConfigurationRevision,
                ChainAbsence::ReceiptMissing,
            ),
        },
        match receipt {
            Some(receipt) => ChainStageBinding::recorded(
                ChainStage::GeneratedArtifactDigest,
                receipt.store_bootstrap_descriptor_digest.as_str(),
            ),
            None => ChainStageBinding::absent(
                ChainStage::GeneratedArtifactDigest,
                ChainAbsence::ReceiptMissing,
            ),
        },
        match receipt {
            Some(receipt) => ChainStageBinding::recorded(
                ChainStage::InstallerReceipt,
                receipt.effect_id.as_str(),
            ),
            None => ChainStageBinding::absent(
                ChainStage::InstallerReceipt,
                ChainAbsence::ReceiptMissing,
            ),
        },
        ChainStageBinding::recorded(
            ChainStage::InstalledPathIdentity,
            launch.authority_descriptor_path.as_str(),
        ),
        match readback {
            WatchdogRuntimeReadback::Matching { .. } => {
                ChainStageBinding::recorded(ChainStage::ActiveRegistration, service_name)
            }
            WatchdogRuntimeReadback::Absent
            | WatchdogRuntimeReadback::Mismatched
            | WatchdogRuntimeReadback::Unknown => ChainStageBinding::absent(
                ChainStage::ActiveRegistration,
                ChainAbsence::RegistrationUnobservable,
            ),
        },
        match bridge {
            Some(path) => ChainStageBinding::recorded(ChainStage::BridgeExecutableIdentity, path),
            None => ChainStageBinding::absent(
                ChainStage::BridgeExecutableIdentity,
                ChainAbsence::OwnerNotAdmitted,
            ),
        },
        ChainStageBinding::recorded(
            ChainStage::RuntimeAdapterFingerprint,
            launch.watchdog_executable_path.as_str(),
        ),
    ]
}

fn chain_links(receipt: Option<&ActivePhaseBRebindReceipt>) -> Vec<DeclaredTransformation> {
    let link = |from, to, kind: &str, revision: Option<&str>| DeclaredTransformation {
        from,
        to,
        kind: kind.to_owned(),
        revision: revision.unwrap_or("unrecorded").to_owned(),
    };
    let pair_digest = receipt
        .and_then(|receipt| receipt.agent_bridge.as_ref())
        .map(|binding| binding.pair_digest.as_str());
    vec![
        link(
            ChainStage::TrackedSourceVersion,
            ChainStage::GeneratorConfigurationRevision,
            "candidate-manifest-digest",
            receipt.map(|receipt| receipt.manifest_digest.as_str()),
        ),
        link(
            ChainStage::GeneratorConfigurationRevision,
            ChainStage::GeneratedArtifactDigest,
            "phase-b-store-bootstrap-digest",
            receipt.map(|receipt| receipt.store_bootstrap_descriptor_digest.as_str()),
        ),
        link(
            ChainStage::GeneratedArtifactDigest,
            ChainStage::InstallerReceipt,
            "phase-b-rebind-receipt-digest",
            receipt.map(|receipt| receipt.receipt_digest.as_str()),
        ),
        link(
            ChainStage::InstallerReceipt,
            ChainStage::InstalledPathIdentity,
            "phase-b-effect-identity",
            receipt.map(|receipt| receipt.effect_id.as_str()),
        ),
        link(
            ChainStage::InstalledPathIdentity,
            ChainStage::ActiveRegistration,
            "phase-b-request-digest",
            receipt.map(|receipt| receipt.request_digest.as_str()),
        ),
        link(
            ChainStage::ActiveRegistration,
            ChainStage::BridgeExecutableIdentity,
            "bridge-pair-digest",
            pair_digest,
        ),
        link(
            ChainStage::BridgeExecutableIdentity,
            ChainStage::RuntimeAdapterFingerprint,
            "phase-b-host-owner-epoch",
            receipt.map(|receipt| receipt.host_owner_epoch.as_str()),
        ),
        link(
            ChainStage::RuntimeAdapterFingerprint,
            ChainStage::LiveEventReadback,
            "phase-b-host-process-identity",
            receipt.map(|receipt| receipt.host_process_identity.as_str()),
        ),
    ]
}
