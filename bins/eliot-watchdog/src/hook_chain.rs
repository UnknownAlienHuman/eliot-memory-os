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

use crate::WatchdogRuntimeReadback;
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainMember {
    pub member_id: String,
    /// Interception/endpoint ownership this member claims. Two observed
    /// members claiming one ownership are competing registrations, not two
    /// legitimate independent applications.
    pub ownership_claim: String,
    /// Identity this member actually presented.
    pub identity: String,
}

impl ChainMember {
    fn new(
        member_id: impl Into<String>,
        ownership_claim: impl Into<String>,
        identity: impl Into<String>,
    ) -> Result<Self, ChainError> {
        let member = Self {
            member_id: member_id.into(),
            ownership_claim: ownership_claim.into(),
            identity: identity.into(),
        };
        if member.member_id.trim().is_empty()
            || member.ownership_claim.trim().is_empty()
            || member.identity.trim().is_empty()
        {
            return Err(ChainError::InvalidMember(member.member_id));
        }
        Ok(member)
    }
}

/// Competing observed members claiming one interception/endpoint ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberReconciliation {
    pub expected: Vec<ChainMember>,
    pub observed: Vec<ChainMember>,
    pub missing: Vec<ChainMember>,
    pub conflicting: Vec<ConflictingOwnership>,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
        scope_enumerated: bool,
        live_readback: LiveEventReadbackSet,
    ) -> Result<Self, ChainError> {
        let stages = with_live_readback_stage(stages, &live_readback);
        validate_stage_set(&stages)?;
        validate_links(&links)?;
        let members = reconcile_members(expected, observed, scope_enumerated);
        let health = if !members.conflicting.is_empty() {
            ChainHealth::Conflicting
        } else if stages.iter().any(|stage| stage.value.is_none())
            || !members.missing.is_empty()
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
    scope_enumerated: bool,
) -> MemberReconciliation {
    let missing: Vec<ChainMember> = expected
        .iter()
        .filter(|member| !observed.iter().any(|row| row.member_id == member.member_id))
        .cloned()
        .collect();
    let mut conflicting: Vec<ConflictingOwnership> = Vec::new();
    // An observed member that presents an identity other than the approved
    // one is a competing registration claiming that interception/endpoint
    // ownership, not the approved member.
    for member in &observed {
        if let Some(approved) = expected
            .iter()
            .find(|row| row.member_id == member.member_id)
            && !windows_paths_equal(Path::new(&approved.identity), Path::new(&member.identity))
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
        conflicting,
        scope_enumerated,
    }
}

fn push_conflict(
    conflicting: &mut Vec<ConflictingOwnership>,
    ownership_claim: &str,
    members: Vec<ChainMember>,
) {
    if !conflicting
        .iter()
        .any(|row| row.ownership_claim == ownership_claim)
    {
        conflicting.push(ConflictingOwnership {
            ownership_claim: ownership_claim.to_owned(),
            members,
        });
    }
}

fn observed_registration_member(
    readback: &WatchdogRuntimeReadback,
    expected: &ChainMember,
) -> Option<ChainMember> {
    // Active registrations are observed, not read from a configuration copy:
    // an SCM acknowledgement without a handle-bound process identity is not a
    // member observation.
    let WatchdogRuntimeReadback::Matching {
        process: Some(process),
        ..
    } = readback
    else {
        return None;
    };
    // The identity is the one the live process actually presented, so a
    // substituted image is visible as a different member identity instead of
    // being accepted as the approved one.
    Some(ChainMember {
        member_id: expected.member_id.clone(),
        ownership_claim: expected.ownership_claim.clone(),
        identity: process.image_path.clone(),
    })
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
                    crate::diagnostics::observe_integration_chain_owner_unavailable(owner, source);
                }
                return Err(error);
            }
        };
        crate::diagnostics::observe_integration_chain(chain.health);
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
        let (approved_host, _) =
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
        let expected = ChainMember::new(
            service_name.clone(),
            service_name.clone(),
            approved_host.request.binary_path().display().to_string(),
        )?;
        let observed = observed_registration_member(&readback, &expected)
            .into_iter()
            .collect();
        IntegrationChain::assemble(
            "installer-approved-watchdog-registration",
            chain_stages(&manifest, receipt, &readback, &service_name),
            chain_links(receipt),
            vec![expected],
            observed,
            // No admitted owner enumerates the complete registration scope for
            // this contour, so extra members stay unobservable instead of
            // being reported as absent.
            false,
            LiveEventReadbackSet {
                owner: "watchdog:hook-chain".to_owned(),
                // The ten logical events have no admitted live readback owner
                // in this contour: this cell reads the installation chain and
                // the active registration, never a host hook event. The empty
                // set is an explicit absence, so the chain is
                // `INSTALLED_UNOBSERVED` rather than healthy.
                events: Vec::new(),
            },
        )
    }
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
