//! Installation discovery identity, catalogue contracts and the accepted
//! catalogue loader.
//!
//! The discovery survey follows Architecture `A11.2` and Implementation
//! `I3.2`, `I3.3.1`: it records safe, detection-first recipes without turning
//! presence into admission or a catalogue into a capability registry. The
//! Windows path identity keeps runtime-root validation lexical and bounded;
//! it does not grant authority or establish external process ownership.
//!
//! `I3.3.1` requires the System Owner to accept catalogue revisions "through
//! the normal installation/configuration path", so this module loads the
//! catalogue from the ACTUAL retained bytes of that existing signed
//! configuration publication rather than from a self-declared revision string:
//! a revision number that merely claims to have been accepted proves nothing
//! about who accepted it or what they accepted. The loader therefore reads the
//! retained record through the existing durable owner, verifies it against the
//! installation-pinned trust anchor, and refuses unless the verified retained
//! content is exactly the content an already-admitted setup binding accepted.
//! Missing, conflicting, stale, foreign-platform or unbounded catalogue input
//! is refused; no unsigned permissive default is ever substituted.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use eliot_config::initial_snapshot::{
    InitialConfigSnapshotTrustAnchor, InitialSnapshotError, InitialSnapshotVerificationContext,
};

use super::setup_binding::profile_ref;
use super::managed_effect_recipe::ManagedEffectRecipe;
use super::{
    BoundedProbeInvocation, InstallationError, InstallationSurvey, PlatformHandle,
    RedbInstallationTransactionStore, SurveyInputObservation, SurveyObservationSource,
    SurveyStage, SurveyStageOutcome, VerifiedSetupBinding, handle, handles, text,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct WindowsPathIdentity {
    pub(crate) prefix: String,
    pub(crate) components: Vec<String>,
}



impl WindowsPathIdentity {
    pub(crate) fn parse_root(value: &str, field: &str) -> Result<Self, InstallationError> {
        text(value, field)?;
        let value = value.replace('/', "\\");
        let lower = value.to_ascii_lowercase();
        if lower.starts_with("\\\\?\\")
            || lower.starts_with("\\\\.\\")
            || lower.starts_with("\\??\\")
            || lower.starts_with("\\\\??\\")
            || lower.starts_with("\\device\\")
            || lower.starts_with("\\\\device\\")
            || lower.starts_with("\\globalroot\\")
            || lower.starts_with("\\\\globalroot\\")
        {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason:
                    "Windows device, NT and verbatim prefixes are not admitted for runtime roots"
                        .to_owned(),
            });
        }

        let (prefix, body) = if let Some(body) = value.strip_prefix("\\\\") {
            let mut parts = body.split('\\');
            let server = parts.next().unwrap_or_default();
            let share = parts.next().unwrap_or_default();
            if server.is_empty() || share.is_empty() {
                return Err(InstallationError::InvalidField {
                    field: field.to_owned(),
                    reason: "UNC runtime root must include server and share components".to_owned(),
                });
            }
            (
                format!(
                    "\\\\{}\\{}",
                    server.to_ascii_lowercase(),
                    share.to_ascii_lowercase()
                ),
                parts.collect::<Vec<_>>(),
            )
        } else if value.len() >= 3
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value.as_bytes()[1] == b':'
            && value.as_bytes()[2] == b'\\'
        {
            (
                value[..2].to_ascii_lowercase(),
                value[3..].split('\\').collect::<Vec<_>>(),
            )
        } else {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason: "runtime root must be an absolute drive or UNC path".to_owned(),
            });
        };

        let mut components = Vec::new();
        for component in body {
            if component.is_empty() {
                continue;
            }
            if component == "." || component == ".." {
                return Err(InstallationError::InvalidField {
                    field: field.to_owned(),
                    reason: "runtime root must not contain dot or parent traversal components"
                        .to_owned(),
                });
            }
            if component.ends_with(' ') || component.ends_with('.') || component.contains(':') {
                return Err(InstallationError::InvalidField {
                    field: field.to_owned(),
                    reason: "runtime root contains a Windows lexical alias component".to_owned(),
                });
            }
            components.push(component.to_ascii_lowercase());
        }
        if components.is_empty() {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason: "volume roots are not admitted as mutable runtime roots".to_owned(),
            });
        }
        Ok(Self { prefix, components })
    }

    pub(crate) fn contains(&self, candidate: &Self) -> bool {
        self.prefix == candidate.prefix
            && self.components.len() <= candidate.components.len()
            && self
                .components
                .iter()
                .zip(&candidate.components)
                .all(|(left, right)| left == right)
    }

    pub(crate) fn aliases_or_overlaps(&self, other: &Self) -> bool {
        self.contains(other) || other.contains(self)
    }

    pub(crate) fn ends_with(&self, suffix: &[&str]) -> bool {
        self.components.len() >= suffix.len()
            && self.components[self.components.len() - suffix.len()..]
                .iter()
                .map(String::as_str)
                .eq(suffix.iter().copied())
    }
}

/// Broad discovery family used by the catalogue; presence is not admission.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationCategory {
    /// Agent runtime, host or ACP/stdio surface.
    AgentRuntime,
    /// Editor or professional application host.
    EditorHost,
    /// Local model runtime.
    LocalModelRuntime,
    /// MCP server or bridge.
    McpServer,
    /// Code-intelligence provider.
    CodeIntelligence,
    /// Database or store runtime.
    Database,
    /// Compiler, language server or development toolchain.
    Toolchain,
    /// Package manager or installer surface.
    PackageManager,
    /// Browser or professional tool.
    BrowserProfessionalTool,
    /// Cloud CLI or remote integration.
    CloudCli,
}

/// The only behaviours a catalogue probe may declare.
///
/// There is deliberately no variant that installs, mutates, starts, stops or
/// authenticates. A probe contract is therefore *structurally* incapable of
/// expressing a harmful behaviour rather than being trusted to refrain from
/// one, which is what `I3.3` step 3 requires: harmlessness must be established
/// before the probe runs, not cleaned up afterwards.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeBehaviour {
    /// Report the executable's own version and exit.
    ReportOwnVersion,
    /// Report bounded usage text and exit.
    ReportOwnUsage,
}

impl ProbeBehaviour {
    /// The closed set of arguments this behaviour may be invoked with.
    ///
    /// `--version` is not inherently safe for an unknown executable, so the
    /// argument is only meaningful next to the exact executable identity the
    /// survey already resolved. The set is closed: no caller shell text and no
    /// arbitrary flag can ever reach a probe.
    const fn admitted_arguments(self) -> &'static [&'static str] {
        match self {
            Self::ReportOwnVersion => &["--version", "-V", "version"],
            Self::ReportOwnUsage => &["--help", "-h", "help"],
        }
    }

    /// Resolves one declared argument for this behaviour.
    fn admits(self, argument: &str) -> bool {
        self.admitted_arguments().contains(&argument)
    }
}

/// Finite probe bounds, validated before any probe runs.
pub const MAX_PROBE_TIMEOUT_MS: u64 = 30_000;
pub const MAX_PROBE_OUTPUT_BYTES: u64 = 64 * 1024;
pub const MAX_PROBE_DESCENDANT_PROCESSES: u32 = 0;
pub const MAX_PROBE_ARGUMENT_BYTES: usize = 64;
pub const MAX_PROBE_ENVIRONMENT_NAMES: usize = 8;

/// The closed set of environment variable names a bounded probe may see.
///
/// A probe receives a scrubbed environment built from these names only, so no
/// token, key, credential or session value can reach the surveyed process
/// through inheritance. Names are non-secret and fixed; a probe cannot
/// introduce a name, and no value is ever carried in the catalogue.
pub const NON_SECRET_PROBE_ENVIRONMENT_NAMES: &[&str] = &[
    "LANG",
    "LC_ALL",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
];

/// One bounded, non-secret probe contract declared by a catalogue recipe.
///
/// This is the whole of what a catalogue may say about executing something: a
/// fixed behaviour, a fixed admitted argument for that behaviour, the exact
/// executable identity that behaviour may be invoked on, finite time/output/
/// descendant bounds, a permitted working area, and an allowlisted
/// non-secret environment name list. Validation is what makes it provably
/// harmless *before* it runs; nothing here cleans up after a probe.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedSafeProbe {
    /// Stable probe recipe identity.
    pub probe_id: PlatformHandle,
    /// The exact validated executable identity this probe may be invoked on.
    ///
    /// It is matched against the identity the survey's file version/signature
    /// stage actually observed. A name found in PATH is not this value, so a
    /// probe can never be invoked on a merely-found program.
    pub executable_identity: PlatformHandle,
    /// The fixed behaviour this probe performs.
    pub behaviour: ProbeBehaviour,
    /// The single fixed argument this behaviour is invoked with.
    pub argument: PlatformHandle,
    /// Finite wall-clock bound in milliseconds.
    pub timeout_ms: u64,
    /// Finite retained output bound in bytes.
    pub max_output_bytes: u64,
    /// Finite descendant-process bound.
    pub max_descendant_processes: u32,
    /// The only working area this probe may be invoked in.
    pub working_area: PlatformHandle,
    /// Non-secret environment variable names visible to this probe.
    pub environment_names: Vec<PlatformHandle>,
}

impl BoundedSafeProbe {
    /// Validates that this probe is bounded, non-secret and behaviourally
    /// inert before any executor may consider running it.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.probe_id, "bounded_probe.probe_id")?;
        handle(
            &self.executable_identity,
            "bounded_probe.executable_identity",
        )?;
        handle(&self.working_area, "bounded_probe.working_area")?;
        let argument = self.argument.as_str();
        if argument.len() > MAX_PROBE_ARGUMENT_BYTES || !self.behaviour.admits(argument) {
            return Err(InstallationError::InvalidField {
                field: "bounded_probe.argument".to_owned(),
                reason: "must be one fixed argument admitted for this probe behaviour".to_owned(),
            });
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_PROBE_TIMEOUT_MS {
            return Err(InstallationError::InvalidField {
                field: "bounded_probe.timeout_ms".to_owned(),
                reason: format!("must be within 1..={MAX_PROBE_TIMEOUT_MS}"),
            });
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > MAX_PROBE_OUTPUT_BYTES {
            return Err(InstallationError::InvalidField {
                field: "bounded_probe.max_output_bytes".to_owned(),
                reason: format!("must be within 1..={MAX_PROBE_OUTPUT_BYTES}"),
            });
        }
        if self.max_descendant_processes > MAX_PROBE_DESCENDANT_PROCESSES {
            return Err(InstallationError::InvalidField {
                field: "bounded_probe.max_descendant_processes".to_owned(),
                reason: format!("must not exceed {MAX_PROBE_DESCENDANT_PROCESSES}"),
            });
        }
        if self.environment_names.len() > MAX_PROBE_ENVIRONMENT_NAMES {
            return Err(InstallationError::InvalidField {
                field: "bounded_probe.environment_names".to_owned(),
                reason: format!("must not exceed {MAX_PROBE_ENVIRONMENT_NAMES} names"),
            });
        }
        for name in &self.environment_names {
            if !NON_SECRET_PROBE_ENVIRONMENT_NAMES.contains(&name.as_str()) {
                return Err(InstallationError::InvalidField {
                    field: "bounded_probe.environment_names".to_owned(),
                    reason: "must name only the admitted non-secret environment variables"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// One exact, resolved, bounded probe invocation.
///
/// This is the whole authority a probe execution ever receives. It is produced
/// by resolution, never by a caller: the executable identity is the identity the
/// survey's file version/signature stage observed, the argument is one fixed
/// argument admitted for the declared behaviour, the bounds are finite, and the
/// environment is a closed non-secret name allowlist. Holding one of these
/// still authorises no installation and no capability; it is the frozen
/// argument contract an admitted effect executor must honour.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedProbeInvocation {
    /// Catalogue family the probe belongs to.
    pub family_id: PlatformHandle,
    /// The catalogue probe recipe identity.
    pub probe_id: PlatformHandle,
    /// The exact observed executable identity the probe may be invoked on.
    pub executable_identity: PlatformHandle,
    /// The fixed behaviour this invocation performs.
    pub behaviour: ProbeBehaviour,
    /// The single fixed argument this invocation passes.
    pub argument: PlatformHandle,
    /// Finite wall-clock bound in milliseconds.
    pub timeout_ms: u64,
    /// Finite retained output bound in bytes.
    pub max_output_bytes: u64,
    /// Finite descendant-process bound.
    pub max_descendant_processes: u32,
    /// The only working area this invocation may run in.
    pub working_area: PlatformHandle,
    /// Non-secret environment variable names visible to this invocation.
    pub environment_names: Vec<PlatformHandle>,
}

/// Resolves the one bounded probe invocation admitted for `observed_identity`,
/// or `None` when this recipe admits none.
///
/// Three refusals are structural rather than conventional:
///
/// 1. a catalogue's `safe_probes` list alone never admits an invocation. It is
///    detection data; a non-empty string list is not permission to execute the
///    discovered program, so the list is never read here;
/// 2. a declared `bounded_probes` contract is admitted only when its
///    `executable_identity` is exactly the identity the survey observed. A name
///    found on PATH, a directory match or a display name never resolves a probe;
/// 3. every field of the resolved invocation was already validated by
///    [`BoundedSafeProbe::validate`] during catalogue validation, so the
///    harmlessness of this invocation is established *before* anything runs and
///    there is nothing to clean up afterwards.
///
/// # Errors
/// Returns [`InstallationError`] when the catalogue is invalid.
pub fn resolve_bounded_probe(
    catalogue: &IntegrationDiscoveryCatalogue,
    family_id: &PlatformHandle,
    observed_identity: &PlatformHandle,
) -> Result<Option<BoundedProbeInvocation>, InstallationError> {
    let entry = catalogue.entry(family_id)?;
    let Some(probe) = entry
        .bounded_probes
        .iter()
        .find(|probe| &probe.executable_identity == observed_identity)
    else {
        return Ok(None);
    };
    // Re-validate at resolution time so the bound asserted by this invocation
    // is proven here, not merely asserted by an earlier catalogue load.
    probe.validate()?;
    Ok(Some(BoundedProbeInvocation {
        family_id: entry.family_id.clone(),
        probe_id: probe.probe_id.clone(),
        executable_identity: probe.executable_identity.clone(),
        behaviour: probe.behaviour,
        argument: probe.argument.clone(),
        timeout_ms: probe.timeout_ms,
        max_output_bytes: probe.max_output_bytes,
        max_descendant_processes: probe.max_descendant_processes,
        working_area: probe.working_area.clone(),
        environment_names: probe.environment_names.clone(),
    }))
}

/// One versioned, detection-first discovery recipe.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationDiscoveryCatalogueEntry {
    /// Stable family identity.
    pub family_id: PlatformHandle,
    /// Discovery category.
    pub category: IntegrationCategory,
    /// Platforms on which the recipe is valid.
    pub supported_platforms: Vec<PlatformHandle>,
    /// Known executable/config/manifest locations.
    pub known_locations: Vec<PlatformHandle>,
    /// Safe discovery or negative-capability probes.
    ///
    /// This is detection data only. A non-empty list is never permission to
    /// execute anything, and no admission decision reads it; only
    /// [`Self::bounded_probes`] can admit an invocation.
    pub safe_probes: Vec<PlatformHandle>,
    /// Bounded, non-secret probe contracts that may be executed.
    pub bounded_probes: Vec<BoundedSafeProbe>,
    /// Official install/update/remove surfaces.
    ///
    /// Detection/advisory references only. A managed effect is admitted only
    /// from [`Self::managed_effects`] after the retained signed publication
    /// authenticates the exact typed recipe.
    pub managed_surfaces: Vec<PlatformHandle>,
    /// Exact typed managed effects, one row per action. An empty list is a
    /// valid detection-only entry; an action not listed here has no effect
    /// recipe and is refused.
    #[serde(default)]
    pub managed_effects: Vec<ManagedEffectRecipe>,
    /// Required execution identities or credential references.
    pub credential_refs: Vec<PlatformHandle>,
    /// License, supply-chain and privacy notes.
    pub assurance_refs: Vec<PlatformHandle>,
    /// Candidate adapter/bridge identities.
    pub adapter_candidates: Vec<PlatformHandle>,
    /// Evidence expiry in Unix milliseconds, if bounded.
    pub evidence_expiry_ms: Option<u64>,
    /// Families this recipe declares as depending on it.
    ///
    /// This is the whole declared edge set used to select affected dependents.
    /// Order never comes from iteration, filesystem, PATH or startup order.
    pub declared_dependents: Vec<PlatformHandle>,
}

impl IntegrationDiscoveryCatalogueEntry {
    /// Validates the recipe and requires at least one safe discovery surface.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.family_id, "family_id")?;
        // Check every finite count before `handles` or a nested recipe/probe
        // validator walks any caller-owned vector.
        if self.supported_platforms.len() > MAX_ENTRY_REFS
            || self.known_locations.len() > MAX_ENTRY_LOCATIONS
            || self.safe_probes.len() > MAX_ENTRY_PROBES
            || self.managed_surfaces.len() > MAX_ENTRY_REFS
            || self.credential_refs.len() > MAX_ENTRY_REFS
            || self.assurance_refs.len() > MAX_ENTRY_REFS
            || self.adapter_candidates.len() > MAX_ENTRY_REFS
            || self.declared_dependents.len() > MAX_ENTRY_REFS
        {
            return Err(InstallationError::InvalidField {
                field: "entry".to_owned(),
                reason: "exceeds a finite catalogue field limit".to_owned(),
            });
        }
        if self.bounded_probes.len() > MAX_ENTRY_PROBES {
            return Err(InstallationError::InvalidField {
                field: "bounded_probes".to_owned(),
                reason: format!("must not exceed {MAX_ENTRY_PROBES} probes"),
            });
        }
        if self.managed_effects.len() > 6 {
            return Err(InstallationError::InvalidField {
                field: "managed_effects".to_owned(),
                reason: "must contain at most one recipe for each managed action".to_owned(),
            });
        }

        handles(&self.supported_platforms, "supported_platforms", true)?;
        handles(&self.known_locations, "known_locations", true)?;
        handles(&self.safe_probes, "safe_probes", true)?;
        handles(&self.managed_surfaces, "managed_surfaces", false)?;
        handles(&self.credential_refs, "credential_refs", false)?;
        handles(&self.assurance_refs, "assurance_refs", true)?;
        handles(&self.adapter_candidates, "adapter_candidates", false)?;
        handles(&self.declared_dependents, "declared_dependents", false)?;
        for location in &self.known_locations {
            if u64::try_from(location.as_str().len()).unwrap_or(u64::MAX)
                > MAX_ENTRY_KNOWN_LOCATION_BYTES
            {
                return Err(InstallationError::InvalidField {
                    field: "known_locations".to_owned(),
                    reason: format!(
                        "must not exceed {MAX_ENTRY_KNOWN_LOCATION_BYTES} bytes per location"
                    ),
                });
            }
        }
        let mut effect_actions = Vec::new();
        for recipe in &self.managed_effects {
            recipe.validate()?;
            if recipe.target_family != self.family_id {
                return Err(InstallationError::IdentityConflict);
            }
            if effect_actions.contains(&recipe.action) {
                return Err(InstallationError::Duplicate {
                    kind: "managed effect action".to_owned(),
                    identity: format!("{}:{:?}", self.family_id.as_str(), recipe.action),
                });
            }
            effect_actions.push(recipe.action);
        }
        let mut probe_ids = BTreeSet::new();
        let mut probe_identities = BTreeSet::new();
        for probe in &self.bounded_probes {
            probe.validate()?;
            if !probe_ids.insert(probe.probe_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "bounded probe".to_owned(),
                    identity: probe.probe_id.as_str().to_owned(),
                });
            }
            if !probe_identities.insert(probe.executable_identity.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "bounded probe executable identity".to_owned(),
                    identity: probe.executable_identity.as_str().to_owned(),
                });
            }
        }
        if self.declared_dependents.contains(&self.family_id) {
            return Err(InstallationError::InvalidField {
                field: "declared_dependents".to_owned(),
                reason: "a family may not declare itself as a dependent".to_owned(),
            });
        }
        if self.evidence_expiry_ms == Some(0) {
            return Err(InstallationError::InvalidField {
                field: "evidence_expiry_ms".to_owned(),
                reason: "must be absent or positive".to_owned(),
            });
        }
        Ok(())
    }

    /// Returns the exact typed signed effect for this action, when the
    /// catalogue declares one. The descriptive `managed_surfaces` labels are
    /// never consulted here.
    #[must_use]
    pub(crate) fn managed_effect_for(
        &self,
        action: super::ManagedEnvironmentAction,
    ) -> Option<&ManagedEffectRecipe> {
        self.managed_effects
            .iter()
            .find(|recipe| recipe.action == action)
    }
}

/// Schema marker for an accepted discovery catalogue publication.
pub const DISCOVERY_CATALOGUE_SCHEMA: &str = "eliot.integration-discovery-catalogue.v1";

/// Configuration setting key the System Owner publishes an accepted discovery
/// catalogue revision under, inside the existing signed configuration payload.
///
/// The catalogue is therefore carried by the existing signed/versioned
/// configuration publication owner and its exact retained bytes, rather than
/// by a second catalogue registry.
pub const DISCOVERY_CATALOGUE_SETTING_KEY: &str = "integration.discovery_catalogue";

/// Configuration setting key holding exact owner-signed managed-change
/// approvals in the same retained snapshot as the catalogue.
pub const MANAGED_CHANGE_APPROVALS_SETTING_KEY: &str = "installation.managed_change_approvals";

/// Schema marker for the signed managed-change approval setting.
pub const MANAGED_CHANGE_APPROVALS_SCHEMA: &str = "eliot.managed-change-approvals.v1";

/// Maximum approvals admitted from one signed configuration snapshot.
pub const MAX_MANAGED_CHANGE_APPROVALS: usize = 256;

/// The only value prefix an inline configuration setting may carry. The
/// configuration owner already uses `literal:` for deterministic values.
pub const LITERAL_VALUE_PREFIX: &str = "literal:";

/// One System Owner approval over an exact managed-change request and the
/// setup/catalogue state it is bound to.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedChangeApproval {
    /// Stable approval identity.
    pub approval_id: PlatformHandle,
    /// Complete request body approved by the signer. Equality is structural
    /// and every request field is checked before plan compilation.
    pub request: super::ManagedEnvironmentChangeRequest,
    /// Catalogue origin the approval applies to.
    pub catalogue_origin: PlatformHandle,
    /// Exact catalogue revision the approval applies to.
    pub catalogue_revision: u64,
    /// Owner identity whose signature on the retained setting carries this
    /// approval.
    pub approved_by: PlatformHandle,
    /// Profile admitted by the setup binding when approval was issued.
    pub profile: super::InstallationProfile,
    /// Runtime-root topology digest admitted when approval was issued.
    pub runtime_state_roots_digest: PlatformHandle,
    /// Setup binding revision admitted when approval was issued.
    pub setup_revision: u64,
    /// Canonical identity of the signed configuration snapshot the approval
    /// was issued against. This is `ConfigPolicySnapshot.snapshot_id`, not the
    /// containing envelope digest; the latter is bound separately by the
    /// immutable plan to avoid a self-referential signature.
    pub snapshot_id: PlatformHandle,
    /// Approval expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl ManagedChangeApproval {
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.approval_id, "managed_change_approval.approval_id")?;
        self.request.validate()?;
        for (value, field) in [
            (&self.catalogue_origin, "catalogue_origin"),
            (&self.approved_by, "approved_by"),
            (&self.runtime_state_roots_digest, "runtime_state_roots_digest"),
            (&self.snapshot_id, "snapshot_id"),
        ] {
            handle(value, field)?;
        }
        if self.catalogue_revision == 0 || self.setup_revision == 0 || self.expires_at_ms == 0 {
            return Err(InstallationError::InvalidField {
                field: "managed_change_approval".to_owned(),
                reason: "catalogue revision, setup revision and expiry must be non-zero".to_owned(),
            });
        }
        Ok(())
    }
}

/// Strict versioned approval set carried by the existing signed configuration
/// snapshot. It is not a second approval registry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedChangeApprovalSet {
    /// Strict schema marker.
    pub schema: PlatformHandle,
    /// Owner-approved exact requests, unique by approval and request ID.
    pub approvals: Vec<ManagedChangeApproval>,
}

impl ManagedChangeApprovalSet {
    /// Validates boundedness and uniqueness before any request is matched.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.schema, MANAGED_CHANGE_APPROVALS_SETTING_KEY)?;
        if self.schema.as_str() != MANAGED_CHANGE_APPROVALS_SCHEMA {
            return Err(InstallationError::InvalidField {
                field: MANAGED_CHANGE_APPROVALS_SETTING_KEY.to_owned(),
                reason: "approval-set schema is not the current strict version".to_owned(),
            });
        }
        if self.approvals.len() > MAX_MANAGED_CHANGE_APPROVALS {
            return Err(InstallationError::InvalidField {
                field: MANAGED_CHANGE_APPROVALS_SETTING_KEY.to_owned(),
                reason: "approval set exceeds its finite limit".to_owned(),
            });
        }
        let mut approval_ids = BTreeSet::new();
        let mut request_ids = BTreeSet::new();
        for approval in &self.approvals {
            approval.validate()?;
            if !approval_ids.insert(approval.approval_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "managed change approval".to_owned(),
                    identity: approval.approval_id.as_str().to_owned(),
                });
            }
            if !request_ids.insert(approval.request.request_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "managed change approval request".to_owned(),
                    identity: approval.request.request_id.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Immutable ELIOT-owned discovery catalogue, not a capability registry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationDiscoveryCatalogue {
    /// Schema marker; must equal [`DISCOVERY_CATALOGUE_SCHEMA`].
    pub schema: PlatformHandle,
    /// Catalogue origin/provenance reference.
    pub origin: PlatformHandle,
    /// Monotonic catalogue revision.
    pub revision: u64,
    /// Platforms this revision is accepted for.
    pub supported_platforms: Vec<PlatformHandle>,
    /// System Owner who accepted this revision through the installation and
    /// configuration path.
    ///
    /// This is a recorded acceptance, not a proof of one: the loader admits a
    /// catalogue only when the System Owner who signed the retained signed
    /// configuration publication carrying these exact bytes is the System
    /// Owner the installation's admitted setup binding already verified.
    pub accepted_by: PlatformHandle,
    /// Unix milliseconds after which this revision is stale, if bounded.
    pub expires_at_ms: Option<u64>,
    /// Versioned discovery recipes.
    pub entries: Vec<IntegrationDiscoveryCatalogueEntry>,
}

/// Finite traversal limits for an accepted catalogue.
///
/// `I3.3.1` requires finite family, recipe and field limits validated *before*
/// traversal, so a hostile or corrupt publication cannot make the survey walk
/// an unbounded set. These are structural bounds, not budgets: nothing here
/// grants, ranks or schedules work.
pub const MAX_CATALOGUE_FAMILIES: usize = 256;
pub const MAX_ENTRY_LOCATIONS: usize = 64;
pub const MAX_ENTRY_PROBES: usize = 16;
pub const MAX_ENTRY_REFS: usize = 32;
pub const MAX_ENTRY_KNOWN_LOCATION_BYTES: u64 = 4096;

/// The I3.3.1 seed families, as detection-only catalogue data.
///
/// The seed is deliberately broader than the first production route set and is
/// **not** a closed vendor enum: new families arrive as signed/versioned
/// catalogue data. Each entry below is a detection recipe identity only.
/// Listing a family here claims nothing about popularity, quality, readiness,
/// installation, health or support — `I3.3.1`: "Presence in this seed
/// catalogue is not a popularity, quality or production-support claim."
///
/// Completeness is checked against [`INTEGRATION_SEED_FAMILY_IDS`], which is
/// derived from these families independently of the catalogue being loaded, so
/// completeness is never checked against a copy of the list being iterated.
pub const INTEGRATION_SEED_FAMILIES: &[(&str, IntegrationCategory)] = &[
    ("codex_app_server", IntegrationCategory::AgentRuntime),
    ("codex_cli", IntegrationCategory::AgentRuntime),
    ("codex_desktop", IntegrationCategory::AgentRuntime),
    ("claude_code", IntegrationCategory::AgentRuntime),
    ("claude_desktop", IntegrationCategory::AgentRuntime),
    ("claude_agent_sdk", IntegrationCategory::AgentRuntime),
    ("opencode", IntegrationCategory::AgentRuntime),
    ("gemini_cli", IntegrationCategory::AgentRuntime),
    ("cursor_agent", IntegrationCategory::AgentRuntime),
    ("cursor_acp", IntegrationCategory::AgentRuntime),
    ("zed_agent", IntegrationCategory::AgentRuntime),
    ("external_acp_agent", IntegrationCategory::AgentRuntime),
    ("antigravity", IntegrationCategory::AgentRuntime),
    ("github_copilot_agent", IntegrationCategory::AgentRuntime),
    ("github_copilot_cli", IntegrationCategory::AgentRuntime),
    ("cline_extension", IntegrationCategory::AgentRuntime),
    ("roo_code_extension", IntegrationCategory::AgentRuntime),
    ("continue_extension", IntegrationCategory::AgentRuntime),
    ("kiro_cli", IntegrationCategory::AgentRuntime),
    ("goose", IntegrationCategory::AgentRuntime),
    ("aider", IntegrationCategory::AgentRuntime),
    ("openhands", IntegrationCategory::AgentRuntime),
    ("lm_studio", IntegrationCategory::LocalModelRuntime),
    ("llmster", IntegrationCategory::LocalModelRuntime),
    ("ollama", IntegrationCategory::LocalModelRuntime),
    (
        "openai_compatible_local_endpoint",
        IntegrationCategory::LocalModelRuntime,
    ),
    ("visual_studio_code", IntegrationCategory::EditorHost),
    ("jetbrains_ide", IntegrationCategory::EditorHost),
    ("zed", IntegrationCategory::EditorHost),
    ("visual_studio", IntegrationCategory::EditorHost),
    (
        "registered_browser",
        IntegrationCategory::BrowserProfessionalTool,
    ),
    (
        "professional_application",
        IntegrationCategory::BrowserProfessionalTool,
    ),
    ("git", IntegrationCategory::Toolchain),
    ("git_worktree", IntegrationCategory::Toolchain),
    ("rustup", IntegrationCategory::Toolchain),
    ("cargo", IntegrationCategory::Toolchain),
    ("rust_analyzer", IntegrationCategory::Toolchain),
    ("cargo_nextest", IntegrationCategory::Toolchain),
    ("miri", IntegrationCategory::Toolchain),
    ("admitted_cargo_tool", IntegrationCategory::Toolchain),
    ("surrealdb", IntegrationCategory::Database),
    ("codebase_memory_mcp", IntegrationCategory::McpServer),
    ("repowise", IntegrationCategory::CodeIntelligence),
    ("docker", IntegrationCategory::Toolchain),
    ("laboratory_vm", IntegrationCategory::Toolchain),
    ("package_manager", IntegrationCategory::PackageManager),
    ("cloud_cli", IntegrationCategory::CloudCli),
];

/// The independent expected seed-family set used for completeness.
///
/// This is derived from [`INTEGRATION_SEED_FAMILIES`] alone. A catalogue that
/// omits one of these families is refused as incomplete rather than being
/// silently reported as "nothing found", because "not in the catalogue" and
/// "installed" are different facts.
#[must_use]
pub fn integration_seed_family_ids() -> Vec<PlatformHandle> {
    INTEGRATION_SEED_FAMILIES
        .iter()
        .filter_map(|(family_id, _)| PlatformHandle::new(*family_id).ok())
        .collect()
}

impl IntegrationDiscoveryCatalogue {
    /// Validates all entries and rejects duplicate family identities.
    ///
    /// Finite family/recipe/field limits are checked before any per-entry
    /// traversal, so an oversized publication is refused without being walked.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.schema.as_str() != DISCOVERY_CATALOGUE_SCHEMA {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "discovery catalogue schema {} requires explicit migration to {DISCOVERY_CATALOGUE_SCHEMA}",
                    self.schema.as_str()
                ),
            });
        }
        handle(&self.origin, "catalogue.origin")?;
        handle(&self.accepted_by, "catalogue.accepted_by")?;
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "catalogue.revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        if self.expires_at_ms == Some(0) {
            return Err(InstallationError::InvalidField {
                field: "catalogue.expires_at_ms".to_owned(),
                reason: "must be absent or positive".to_owned(),
            });
        }
        if self.entries.is_empty() {
            return Err(InstallationError::IncompleteObservation(
                "an accepted discovery catalogue must declare at least one family".to_owned(),
            ));
        }
        if self.entries.len() > MAX_CATALOGUE_FAMILIES {
            return Err(InstallationError::InvalidField {
                field: "catalogue.entries".to_owned(),
                reason: format!("must not exceed {MAX_CATALOGUE_FAMILIES} families"),
            });
        }
        if self.supported_platforms.len() > MAX_ENTRY_REFS {
            return Err(InstallationError::InvalidField {
                field: "catalogue.supported_platforms".to_owned(),
                reason: format!("must not exceed {MAX_ENTRY_REFS} platform references"),
            });
        }
        handles(
            &self.supported_platforms,
            "catalogue.supported_platforms",
            true,
        )?;
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            if !seen.insert(entry.family_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "catalogue family".to_owned(),
                    identity: entry.family_id.as_str().to_owned(),
                });
            }
        }
        // Every declared dependent must itself be a declared family: an edge to
        // an absent family is a conflicting publication, not a silent no-op.
        for entry in &self.entries {
            for dependent in &entry.declared_dependents {
                if !seen.contains(dependent.as_str()) {
                    return Err(InstallationError::IdentityConflict);
                }
            }
        }
        Ok(())
    }

    /// Checks completeness against the independent I3.3.1 seed set.
    ///
    /// The expected set comes from [`INTEGRATION_SEED_FAMILIES`] alone and is
    /// never derived from `self.entries`, so this is a coverage check and not a
    /// tautology. A seed family that is missing is an explicit gap; it is
    /// never reported as "not installed".
    ///
    /// # Errors
    /// Returns [`InstallationError::IncompleteObservation`] naming every
    /// uncovered seed family when the catalogue does not account for all of
    /// them, or [`InstallationError::IdentityConflict`] when a declared family
    /// claims a seed category it does not hold.
    pub fn require_seed_family_coverage(&self) -> Result<(), InstallationError> {
        self.validate()?;
        let declared_categories = self
            .entries
            .iter()
            .map(|entry| (entry.family_id.clone(), entry.category))
            .collect::<BTreeMap<_, _>>();
        let expected = integration_seed_family_ids();
        let mut uncovered = Vec::new();
        for family_id in &expected {
            let Some(category) = declared_categories.get(family_id) else {
                uncovered.push(family_id.as_str().to_owned());
                continue;
            };
            let Some((_, expected_category)) = INTEGRATION_SEED_FAMILIES
                .iter()
                .find(|(seed_id, _)| *seed_id == family_id.as_str())
            else {
                continue;
            };
            if category != expected_category {
                return Err(InstallationError::IdentityConflict);
            }
        }
        if !uncovered.is_empty() {
            return Err(InstallationError::IncompleteObservation(format!(
                "discovery catalogue accounts for {} of {} I3.3.1 seed families; uncovered: {}",
                expected.len() - uncovered.len(),
                expected.len(),
                uncovered.join(", ")
            )));
        }
        Ok(())
    }

    /// Requires every declared dependent family to exist, then returns the
    /// families the given family declares as depending on it.
    ///
    /// The result is a closure over the declared edge set only: it never
    /// depends on entry order, iteration order or startup order.
    ///
    /// # Errors
    /// Returns [`InstallationError`] when the catalogue is invalid or an edge
    /// names a family the catalogue does not declare.
    pub fn dependents_of(
        &self,
        family_id: &PlatformHandle,
    ) -> Result<Vec<PlatformHandle>, InstallationError> {
        self.validate()?;
        let mut closure = BTreeSet::new();
        let mut frontier = vec![family_id.clone()];
        while let Some(current) = frontier.pop() {
            for entry in &self.entries {
                if entry.declared_dependents.contains(&current)
                    && closure.insert(entry.family_id.clone())
                {
                    frontier.push(entry.family_id.clone());
                }
            }
        }
        closure.remove(family_id);
        Ok(closure.into_iter().collect())
    }

    /// Finds one exact family recipe after validating the catalogue.
    pub fn entry(
        &self,
        family_id: &PlatformHandle,
    ) -> Result<&IntegrationDiscoveryCatalogueEntry, InstallationError> {
        self.validate()?;
        self.entries
            .iter()
            .find(|entry| &entry.family_id == family_id)
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "catalogue family was not found".to_owned(),
                )
            })
    }
}

/// Why an accepted catalogue was refused.
///
/// The failure is typed at every layer: the durable owner's
/// [`InstallationError`], the configuration owner's
/// [`InitialSnapshotError`], and the catalogue-specific conditions below are
/// each preserved rather than flattened into one message.
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum CatalogueAdmissionError {
    /// The durable installation owner refused the load.
    #[error("discovery catalogue load refused by the installation owner: {0}")]
    Installation(#[from] InstallationError),
    /// The signed configuration publication carrying the catalogue is not admitted.
    #[error("discovery catalogue signed publication is not admitted: {0}")]
    Snapshot(#[from] InitialSnapshotError),
    /// No catalogue revision has been published for this installation.
    #[error("no accepted discovery catalogue has been published for this installation")]
    NotPublished,
    /// The catalogue revision has expired against the observed clock.
    #[error("accepted discovery catalogue revision expired at {0} Unix milliseconds")]
    Expired(u64),
    /// The retained publication is not this installation's own publication.
    #[error("accepted discovery catalogue belongs to a different installation")]
    ForeignInstallation,
}

/// The bounded, System Owner accepted discovery catalogue revision.
///
/// This type has no public constructor and no deserializer. The only way to
/// obtain one is [`load_accepted_catalogue`], which reads the *actual retained
/// bytes* of the signed configuration publication through the existing durable
/// owner, verifies them against the installation-pinned trust anchor, and
/// requires that the System Owner who signed them is the System Owner the
/// installation's admitted setup binding already confirmed. A revision or
/// origin string on its own is not a verified signature and is never treated as
/// one: it is a label on content that must itself be retained and verified.
///
/// Holding this value is not capability admission and not permission to
/// install. `I3.3.1`: "catalogue update cannot install software, grant
/// credentials or advertise a capability by itself."
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedIntegrationCatalogue {
    catalogue: IntegrationDiscoveryCatalogue,
    installation_id: String,
    accepted_by: PlatformHandle,
    signed_publication_ref: PlatformHandle,
    approvals: Vec<ManagedChangeApproval>,
}

impl AcceptedIntegrationCatalogue {
    /// Returns the validated catalogue revision.
    #[must_use]
    pub const fn catalogue(&self) -> &IntegrationDiscoveryCatalogue {
        &self.catalogue
    }

    /// Returns the installation identity whose retained publication admitted
    /// this revision.
    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Returns the System Owner whose verified signature admitted this revision.
    #[must_use]
    pub const fn accepted_by(&self) -> &PlatformHandle {
        &self.accepted_by
    }

    /// Returns the retained signed publication reference this revision was
    /// admitted from.
    ///
    /// This is the actual retained content the acceptance is bound to, not a
    /// digest recomputed to make a comparison pass: it is the envelope digest
    /// of the bytes the configuration owner already verified.
    #[must_use]
    pub const fn signed_publication_ref(&self) -> &PlatformHandle {
        &self.signed_publication_ref
    }

    /// Returns the accepted catalogue revision number.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.catalogue.revision
    }

    /// Returns the accepted catalogue origin.
    #[must_use]
    pub const fn origin(&self) -> &PlatformHandle {
        &self.catalogue.origin
    }

    /// Returns whether this revision is valid for the observed platform.
    #[must_use]
    pub fn supports_platform(&self, platform: &PlatformHandle) -> bool {
        self.catalogue
            .supported_platforms
            .iter()
            .any(|supported| supported == platform)
    }

    pub(crate) fn require_approval(
        &self,
        request: &super::ManagedEnvironmentChangeRequest,
        authority: &VerifiedSetupBinding,
        now_ms: u64,
    ) -> Result<ManagedChangeApproval, ManagedChangeApprovalError> {
        let approval = self
            .approvals
            .iter()
            .find(|approval| approval.request.request_id == request.request_id)
            .ok_or_else(|| ManagedChangeApprovalError::Missing(request.request_id.as_str().to_owned()))?;
        if approval.request != *request
            || approval.catalogue_origin != self.catalogue.origin
            || approval.catalogue_revision != self.catalogue.revision
            || approval.approved_by != self.accepted_by
            || approval.approved_by != *authority.confirmed_owner()
            || approval.profile != authority.profile()
            || approval.runtime_state_roots_digest != *authority.runtime_state_roots_digest()
            || approval.setup_revision != authority.setup_revision()
            || approval.snapshot_id.as_str() != authority.snapshot_id()
        {
            return Err(ManagedChangeApprovalError::Stale);
        }
        if now_ms == 0 {
            return Err(ManagedChangeApprovalError::ClockUnavailable);
        }
        if now_ms >= approval.expires_at_ms {
            return Err(ManagedChangeApprovalError::Expired(approval.expires_at_ms));
        }
        Ok(approval.clone())
    }
}

/// Typed refusal when an exact signed approval is absent, stale or expired.
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ManagedChangeApprovalError {
    /// No signed row approves this request identity.
    #[error("no System Owner approval exists for request {0}")]
    Missing(String),
    /// A signed row exists but does not bind the exact request and setup state.
    #[error("the System Owner approval no longer matches the current request or setup")]
    Stale,
    /// Approval expired at this Unix millisecond instant.
    #[error("the System Owner approval expired at {0}")]
    Expired(u64),
    /// Wall-clock time could not be obtained.
    #[error("the current approval time is unavailable")]
    ClockUnavailable,
}

/// Typed failures across the survey-to-plan boundary.
///
/// The catalogue admission failure and the installation failure are each
/// preserved rather than flattened into one message, so a caller can tell an
/// unaccepted catalogue from an invalid request.
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ManagedChangeAdmissionError {
    /// The accepted catalogue revision could not be loaded.
    #[error("managed change: {0}")]
    Catalogue(#[from] CatalogueAdmissionError),
    /// The installation owner refused the survey or the plan.
    #[error("managed change: {0}")]
    Installation(#[from] InstallationError),
    /// Exact owner-signed request approval was missing or no longer current.
    #[error("managed change approval: {0}")]
    Approval(#[from] ManagedChangeApprovalError),
    /// The signed effect recipe requires authority outside the portable adapter.
    #[error("managed change recipe requires unsupported effect: {0:?}")]
    UnsupportedEffect(super::ManagedEffectRequirement),
    /// The signed catalogue has no typed effect for the exact family/action.
    #[error("no signed managed-effect recipe for family {family} action {action:?}")]
    MissingEffectRecipe {
        /// Catalogue family requested.
        family: String,
        /// Request action with no effect recipe.
        action: super::ManagedEnvironmentAction,
    },
}

/// The exact installation, publication, authority, platform and instant one
/// accepted catalogue revision is resolved against.
///
/// These six values travel together at every level of the accepted-catalogue
/// path, so they are grouped here to bind the load, the survey and the compiled
/// plan to *one* admission context by construction rather than by six separate
/// arguments a caller could pair inconsistently.
///
/// The grouping is a naming change and admits nothing on its own. This context
/// carries the installation's own durable store, the transaction whose retained
/// publication is read, the installation-pinned anchor those retained bytes are
/// verified against, the already-admitted authority whose confirmed owner must
/// have signed them, the platform the installation was actually observed on,
/// and the instant expiry is judged at. Every admission rule still lives in
/// [`load_accepted_catalogue`]: a context value is not an accepted catalogue,
/// not a capability, and not permission to install.
pub struct AcceptedCatalogueContext<'a> {
    /// The durable owner the retained signed publication is read from.
    pub store: &'a RedbInstallationTransactionStore,
    /// Transaction whose retained initial snapshot carries that publication.
    pub transaction_id: &'a PlatformHandle,
    /// Installation-pinned trust anchor the retained bytes are verified
    /// against.
    pub anchor: &'a InitialConfigSnapshotTrustAnchor,
    /// The already-admitted authority whose confirmed owner must have signed
    /// that publication.
    pub authority: &'a VerifiedSetupBinding,
    /// The platform the installation was actually observed on.
    pub observed_platform: &'a PlatformHandle,
    /// The instant catalogue expiry is judged at, in Unix milliseconds.
    pub now_ms: u64,
}

/// Admits the accepted catalogue revision, surveys it in the mandatory order,
/// and compiles one request against that exact survey and that exact approval.
///
/// This is the single production path from an accepted catalogue to a frozen
/// plan, and it deliberately owns no execution and no effect. Nothing here
/// installs, starts, stops, reconfigures or removes anything; the durable
/// `I3.15` `InstallationTransaction` remains the single effect owner, and a
/// compiled plan is still only a plan.
///
/// The plan's survey content digest is the digest of the survey this call just
/// produced, so revalidating the plan against a later survey of the same
/// catalogue revision fails when any observation changed.
///
/// # Errors
/// Returns [`ManagedChangeAdmissionError`] when no accepted revision loads for
/// the observed platform, when the survey or catalogue refuses, or when the
/// request cannot be compiled against that exact survey and approval.
pub fn admit_installation_survey_and_compile_change(
    context: &AcceptedCatalogueContext<'_>,
    source: &dyn SurveyObservationSource,
    request: &super::ManagedEnvironmentChangeRequest,
) -> Result<super::AcceptedManagedChange, ManagedChangeAdmissionError> {
    let admitted = survey_accepted_installation(context, source)?;
    let approval = admitted.accepted.require_approval(
        request,
        context.authority,
        super::wall_clock_millis(),
    )?;
    let entry = admitted.accepted.catalogue().entry(&request.target_family)?;
    let effect_recipe = entry
        .managed_effect_for(request.action)
        .ok_or_else(|| ManagedChangeAdmissionError::MissingEffectRecipe {
            family: request.target_family.as_str().to_owned(),
            action: request.action,
        })?;
    if let Err(requirement) = effect_recipe.require_supported() {
        return Err(ManagedChangeAdmissionError::UnsupportedEffect(requirement));
    }
    let plan = super::compile_managed_change_plan(
        request,
        &admitted.accepted,
        &admitted.survey,
        context.authority,
        &approval,
        effect_recipe,
    )?;
    let managed_tools_root = super::managed_change_admission::managed_tools_root(
        context.authority,
        context.store,
        context.transaction_id,
    )?;
    Ok(super::AcceptedManagedChange::new(
        admitted,
        plan,
        managed_tools_root,
    ))
}

/// One ordered, metadata-only survey of the accepted catalogue together with
/// the bounded probe invocations that revision admits.
///
/// The two halves are deliberately separate. The survey reports only what was
/// observed; `admitted_probes` is the exact, already-bounded set an admitted
/// executor may run against identities the survey resolved. Neither half
/// executes anything, and holding this result is not admission, permission to
/// install, or capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedInstallationSurvey {
    /// The bounded, System Owner accepted catalogue revision that was surveyed.
    pub(crate) accepted: AcceptedIntegrationCatalogue,
    /// The ordered metadata-only survey of that exact revision.
    pub(crate) survey: InstallationSurvey,
    /// Every bounded, non-secret probe invocation admitted by that exact
    /// revision for the identities the survey resolved, ascending by family
    /// then probe identity.
    pub(crate) admitted_probes: Vec<BoundedProbeInvocation>,
}

impl AcceptedInstallationSurvey {
    /// The accepted signed catalogue revision observed by this survey.
    #[must_use]
    pub const fn accepted(&self) -> &AcceptedIntegrationCatalogue {
        &self.accepted
    }

    /// The ordered survey result.
    #[must_use]
    pub const fn survey(&self) -> &InstallationSurvey {
        &self.survey
    }

    /// Bounded contracts resolved for exact observed identities. This list is
    /// not permission to execute them.
    #[must_use]
    pub fn admitted_probes(&self) -> &[BoundedProbeInvocation] {
        &self.admitted_probes
    }

    /// Returns the canonical content digest of the exact validated survey
    /// retained by this accepted survey carrier.
    ///
    /// The digest binds the original ordered survey content; validating here
    /// prevents a mutated in-memory survey from being represented by a fresh
    /// digest before the Kernel process owner compares it with its admitted
    /// probe result.
    pub fn survey_content_digest(&self) -> Result<PlatformHandle, InstallationError> {
        self.survey.validate()?;
        super::managed_change_plan::survey_content_digest(&self.survey)
    }

    /// Returns the exact fresh file-version observation backing one admitted
    /// bounded probe invocation.
    ///
    /// This is a read-only join over the same non-deserializable survey and
    /// admitted invocation. It returns `None` unless the exact invocation is
    /// present once, its family and candidate each resolve uniquely, and all
    /// identity-stage observations for that candidate retain one agreeing
    /// file identity and SHA-256 with a readable version-resource result.
    /// The accessor supplies metadata to the original Kernel process owner; it
    /// does not authorize execution or turn a probe result into capability.
    #[must_use]
    pub fn executable_observation_for_probe(
        &self,
        invocation: &BoundedProbeInvocation,
    ) -> Option<&SurveyInputObservation> {
        let mut admitted = self
            .admitted_probes
            .iter()
            .filter(|candidate| *candidate == invocation);
        admitted.next()?;
        if admitted.next().is_some() {
            return None;
        }

        let mut families = self
            .survey
            .families()
            .iter()
            .filter(|family| family.family_id == invocation.family_id);
        let family = families.next()?;
        if families.next().is_some() {
            return None;
        }

        let mut candidates = family
            .candidates
            .iter()
            .filter(|candidate| candidate.observed_identity == invocation.executable_identity);
        let candidate = candidates.next()?;
        if candidates.next().is_some() {
            return None;
        }

        let mut identity_stages = family
            .stages
            .iter()
            .filter(|stage| stage.stage == SurveyStage::FileVersionSignatureIdentity);
        let identity_stage = identity_stages.next()?;
        if identity_stages.next().is_some() {
            return None;
        }

        let mut matching = identity_stage.observations.iter().filter(|observation| {
            observation.outcome == SurveyStageOutcome::Found
                && observation.observed_identity.as_ref() == Some(&invocation.executable_identity)
                && candidate.aliases.contains(&observation.input)
        });
        let first = matching.next()?;
        let first_version = first.file_version.as_ref()?;
        let first_identity = first_version.file_identity.as_ref()?;
        let first_sha256 = first_version.sha256.as_deref()?;
        if !matches!(
            &first_version.outcome,
            eliot_platform_windows::FileVersionOutcome::Present { .. }
                | eliot_platform_windows::FileVersionOutcome::Absent
        ) || !is_lowercase_sha256(first_sha256)
        {
            return None;
        }

        for observation in matching {
            let version = observation.file_version.as_ref()?;
            if !matches!(
                &version.outcome,
                eliot_platform_windows::FileVersionOutcome::Present { .. }
                    | eliot_platform_windows::FileVersionOutcome::Absent
            ) || version.file_identity.as_ref() != Some(first_identity)
                || version.sha256.as_deref() != Some(first_sha256)
                || !is_lowercase_sha256(version.sha256.as_deref()?)
            {
                return None;
            }
        }

        Some(first)
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Surveys the accepted catalogue revision and resolves its bounded probes.
///
/// This is the live edge between the accepted catalogue and the ordered survey:
/// it loads the accepted revision through [`load_accepted_catalogue`], runs the
/// mandatory [`survey_installation`] order against the supplied observation
/// source with **no** probe answers — so the probe stage reports `Withheld`
/// rather than a probe nobody executed — and then resolves, for every identity
/// the identity stage actually observed, the single bounded invocation that
/// revision declares for that exact identity.
///
/// A family whose recipe lists `safe_probes` but declares no bounded contract
/// for the observed identity contributes no invocation at all. That is the
/// structural reason a disallowed or unknown probe does not execute merely
/// because a probe string exists.
///
/// # Errors
/// Returns [`CatalogueAdmissionError`] when no accepted revision can be loaded
/// for the observed platform, or when the catalogue or the observation source
/// refuses the survey.
pub fn survey_accepted_installation(
    context: &AcceptedCatalogueContext<'_>,
    source: &dyn SurveyObservationSource,
) -> Result<AcceptedInstallationSurvey, CatalogueAdmissionError> {
    let accepted = load_accepted_catalogue(context)?;
    let survey = super::survey_installation(accepted.catalogue(), source, &[])?;
    // The probe stage is deliberately answered with an empty answer set: this
    // coordinator runs no process, so the mandatory `I3.3` order ends in
    // `Withheld` for every identity rather than in a probe nobody executed.
    let mut admitted_probes = Vec::new();
    for family in &survey.families {
        for candidate in &family.candidates {
            if let Some(invocation) = super::resolve_bounded_probe(
                accepted.catalogue(),
                &family.family_id,
                &candidate.observed_identity,
            )? {
                admitted_probes.push(invocation);
            }
        }
    }
    admitted_probes.sort_by(|left, right| {
        left.family_id
            .cmp(&right.family_id)
            .then_with(|| left.probe_id.cmp(&right.probe_id))
    });
    Ok(AcceptedInstallationSurvey {
        accepted,
        survey,
        admitted_probes,
    })
}

/// Loads one bounded, System Owner accepted discovery catalogue revision.
///
/// The load reads the retained signed configuration publication named by the
/// supplied [`AcceptedCatalogueContext`] through the existing durable owner
/// ([`RedbInstallationTransactionStore::load_initial_snapshot`]) — the actual
/// retained bytes, not a caller-supplied digest — and admits them only when
/// every one of the following holds:
///
/// 1. the retained envelope verifies against the installation-pinned trust
///    anchor under the context the admitted setup binding already verified;
/// 2. that verification's System Owner is exactly the confirmed owner of the
///    supplied [`VerifiedSetupBinding`], so a catalogue cannot be admitted by
///    an authority that never admitted this installation;
/// 3. the decoded catalogue validates, accounts for the whole independent
///    `I3.3.1` seed set, and declares the observed platform;
/// 4. the catalogue is not expired against the context's `now_ms`.
///
/// Nothing here installs software, grants a credential, mutates PATH or
/// advertises a capability, and an absent publication is an explicit refusal
/// rather than an unsigned permissive default.
///
/// # Errors
/// Returns [`CatalogueAdmissionError`] when the retained publication is
/// absent, not admitted by this installation's anchor, refused by the
/// installation owner, expired, or does not account for the seed set on the
/// observed platform.
pub fn load_accepted_catalogue(
    context: &AcceptedCatalogueContext<'_>,
) -> Result<AcceptedIntegrationCatalogue, CatalogueAdmissionError> {
    handle(context.observed_platform, "catalogue.observed_platform")?;
    let Some(snapshot) = context
        .store
        .load_initial_snapshot(context.transaction_id)?
    else {
        return Err(CatalogueAdmissionError::NotPublished);
    };
    if snapshot.payload.installation_id != context.authority.installation_id() {
        return Err(CatalogueAdmissionError::ForeignInstallation);
    }
    // Verify the ACTUAL retained bytes against the installation-pinned anchor
    // under the exact context the admitted setup binding already confirmed.
    let verification_context = InitialSnapshotVerificationContext {
        installation_id: context.authority.installation_id().to_owned(),
        profile_ref: profile_ref(context.authority.profile())?,
        runtime_state_roots_digest: context
            .authority
            .runtime_state_roots_digest()
            .as_str()
            .to_owned(),
        key_identity: context.authority.confirmed_owner().as_str().to_owned(),
        setup_revision: context.authority.setup_revision(),
    };
    let verified = context.anchor.verify(&snapshot, &verification_context)?;
    // A valid signature and the same canonical snapshot_id are insufficient:
    // the setup owner admitted this exact retained envelope digest.
    if verified.envelope_digest() != context.authority.configuration_snapshot_ref().as_str() {
        return Err(InstallationError::IdentityConflict.into());
    }
    // The retained publication is only this installation's own when the
    // System Owner who signed it is the System Owner that admitted this
    // installation. A revision or origin label proves nothing on its own.
    if verified.signer_id() != context.authority.confirmed_owner().as_str() {
        return Err(CatalogueAdmissionError::ForeignInstallation);
    }
    let signed_publication_ref = PlatformHandle::new(verified.envelope_digest().to_owned())
        .map_err(|error| InstallationError::InvalidField {
            field: "catalogue.signed_publication_ref".to_owned(),
            reason: error.to_string(),
        })?;

    let Some(catalogue) = decode_catalogue_setting(
        verified.payload().snapshot.settings.as_slice(),
        context.authority.confirmed_owner(),
    )?
    else {
        return Err(CatalogueAdmissionError::NotPublished);
    };
    catalogue.validate()?;
    let approvals = decode_approval_setting(
        verified.payload().snapshot.settings.as_slice(),
        context.authority.confirmed_owner(),
    )?;
    catalogue.require_seed_family_coverage()?;
    if !catalogue
        .supported_platforms
        .iter()
        .any(|supported| supported == context.observed_platform)
    {
        return Err(InstallationError::ProfileViolation(format!(
            "accepted discovery catalogue revision {} is not valid for platform {}",
            catalogue.revision,
            context.observed_platform.as_str()
        ))
        .into());
    }
    if catalogue.accepted_by != *context.authority.confirmed_owner() {
        return Err(CatalogueAdmissionError::ForeignInstallation);
    }
    if let Some(expires_at_ms) = catalogue.expires_at_ms
        && context.now_ms >= expires_at_ms
    {
        return Err(CatalogueAdmissionError::Expired(expires_at_ms));
    }

    Ok(AcceptedIntegrationCatalogue {
        installation_id: verified.payload().installation_id.clone(),
        accepted_by: PlatformHandle::new(verified.signer_id().to_owned()).map_err(|error| {
            InstallationError::InvalidField {
                field: "catalogue.accepted_by".to_owned(),
                reason: error.to_string(),
            }
        })?,
        signed_publication_ref,
        catalogue,
        approvals,
    })
}

/// Decodes owner approvals from the same verified retained publication as the
/// catalogue. Missing approval data means no request has been approved; it is
/// never replaced with an unsigned default row.
fn decode_approval_setting(
    settings: &[eliot_config::Setting],
    confirmed_owner: &PlatformHandle,
) -> Result<Vec<ManagedChangeApproval>, CatalogueAdmissionError> {
    let Some(setting) = settings
        .iter()
        .find(|setting| setting.key == MANAGED_CHANGE_APPROVALS_SETTING_KEY)
    else {
        return Ok(Vec::new());
    };
    if setting.owner_ref != confirmed_owner.as_str() {
        return Err(CatalogueAdmissionError::ForeignInstallation);
    }
    let Some(literal) = setting.value_ref.strip_prefix(LITERAL_VALUE_PREFIX) else {
        return Err(InstallationError::InvalidField {
            field: MANAGED_CHANGE_APPROVALS_SETTING_KEY.to_owned(),
            reason: "must carry a literal approval-set payload".to_owned(),
        }
        .into());
    };
    let set: ManagedChangeApprovalSet = serde_json::from_str(literal).map_err(|error| {
        InstallationError::InvalidField {
            field: MANAGED_CHANGE_APPROVALS_SETTING_KEY.to_owned(),
            reason: format!("approval payload is not the current strict shape: {error}"),
        }
    })?;
    set.validate()?;
    if set
        .approvals
        .iter()
        .any(|approval| approval.approved_by != *confirmed_owner)
    {
        return Err(CatalogueAdmissionError::ForeignInstallation);
    }
    Ok(set.approvals)
}

/// Decodes the catalogue revision a System Owner accepted inside one verified
/// signed configuration publication.
///
/// The catalogue travels as one immutable, System Owner owned configuration
/// setting, which is exactly the "signed/versioned configuration publication
/// owner" `I3.3.1` requires. The setting is matched on its exact key and its
/// owner must be the accepting System Owner, so no other setting and no
/// foreign owner can supply a catalogue.
fn decode_catalogue_setting(
    settings: &[eliot_config::Setting],
    confirmed_owner: &PlatformHandle,
) -> Result<Option<IntegrationDiscoveryCatalogue>, CatalogueAdmissionError> {
    let Some(setting) = settings
        .iter()
        .find(|setting| setting.key == DISCOVERY_CATALOGUE_SETTING_KEY)
    else {
        return Ok(None);
    };
    if setting.owner_ref != confirmed_owner.as_str() {
        return Err(CatalogueAdmissionError::ForeignInstallation);
    }
    let Some(literal) = setting.value_ref.strip_prefix(LITERAL_VALUE_PREFIX) else {
        return Err(InstallationError::InvalidField {
            field: DISCOVERY_CATALOGUE_SETTING_KEY.to_owned(),
            reason: "must carry a literal catalogue payload".to_owned(),
        }
        .into());
    };
    serde_json::from_str(literal).map(Some).map_err(|error| {
        InstallationError::InvalidField {
            field: DISCOVERY_CATALOGUE_SETTING_KEY.to_owned(),
            reason: format!("accepted catalogue payload is not the current strict shape: {error}"),
        }
        .into()
    })
}

#[cfg(all(test, windows))]
/// Existing signed-admission fixtures shared with transaction-boundary tests.
pub(crate) mod accepted_managed_change_tests {
    use std::num::NonZeroU64;
    use std::path::Path;

    use eliot_config::initial_snapshot::{
        Ed25519InitialSnapshotSigner, InitialConfigSnapshotTrustAnchor, InitialSnapshotIdentity,
        SignedInitialConfigSnapshot, prepare_initial_snapshot_payload,
    };
    use eliot_config::{PrivacyChoice, Setting, first_run::FirstRunDecision};
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_platform::PlatformHandle;
    use eliot_platform_windows::{PackageFileSpec, PackageManifest, TrustedSourceBundle};
    use tempfile::TempDir;

    use super::*;
    use crate::{
        GenerationPackagePlanInput, GenerationPackagePlanner, InstallationEpoch,
        InstallationProfile, InstallationTransaction, InstallationTransactionStore,
        ManagedEnvironmentAction, ManagedEnvironmentChangeRequest,
        ManagedEffectOperation, ManagedEffectPostcondition, ManagedResourceChange,
        PackageArtifactDigest, RedbInstallationTransactionStore, SetupAdvanceInput,
        SetupBinding, SetupEffectObservation, SetupKeyReference, SetupMilestone,
        SurveyInputObservation, SurveyProbeAnswer, SurveyStage, SurveyStageOutcome,
        admit_installation_survey_and_compile_change, verify_setup_binding,
    };

    const INSTALLATION_ID: &str = "installation:managed-change-proof";
    const OWNER_ID: &str = "owner:managed-change-proof";
    const TARGET_FAMILY: &str = "codex_cli";
    const PACKAGE_VERSION: &str = "1.0.0";
    const PROFILE_GENERATION: &str = "candidate";
    const OBSERVED_PLATFORM: &str = "windows-x86_64";

    fn h(value: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(value.into()).expect("test handle is valid")
    }

    fn digest(value: &[u8]) -> PlatformHandle {
        h(crate::sha256_hex(value))
    }

    fn minimal_pe() -> Vec<u8> {
        let pe_offset = 0x80_usize;
        let optional_size = 0xf0_usize;
        let section_end = pe_offset + 4 + 20 + optional_size + 40;
        let mut bytes = vec![0_u8; section_end];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_offset + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&(optional_size as u16).to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&2_u16.to_le_bytes());
        bytes[coff + 20..coff + 22].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes
    }

    fn planner_file(name: &str, executable: bool) -> Vec<u8> {
        if executable {
            let mut bytes = minimal_pe();
            bytes.extend_from_slice(name.as_bytes());
            bytes
        } else {
            format!("content:{name}").into_bytes()
        }
    }

    struct ManagedBundle {
        _directory: TempDir,
        source: PlatformHandle,
        identity: eliot_platform_windows::FileIdentity,
        manifest: PackageManifest,
        expected_files: Vec<PackageArtifactDigest>,
    }

    impl ManagedBundle {
        fn new() -> Self {
            Self::with_executable_bytes(minimal_pe())
        }

        /// Copies an existing Windows-signed image into a disposable bundle.
        /// The test reads and copies the image; the package path never executes it.
        fn new_system_signed_image() -> Self {
            let system_root = std::env::var_os("SystemRoot")
                .expect("Windows exposes its system root to the signed-image fixture");
            let image = Path::new(&system_root).join("System32").join("where.exe");
            let bytes = std::fs::read(&image)
                .expect("read the existing Windows-signed System32 image without executing it");
            assert!(!bytes.is_empty(), "the signed Windows image is non-empty");
            Self::with_executable_bytes(bytes)
        }

        fn with_executable_bytes(bytes: Vec<u8>) -> Self {
            let directory = TempDir::new().expect("managed bundle directory");
            std::fs::write(directory.path().join("codex.exe"), &bytes)
                .expect("write test package executable");
            let source = TrustedSourceBundle::open(directory.path())
                .expect("open exact managed source bundle");
            let identity = source.identity();
            let manifest = PackageManifest::new(
                format!("{TARGET_FAMILY}/{PACKAGE_VERSION}"),
                vec![PackageFileSpec::new(
                    "codex.exe",
                    true,
                    bytes.len() as u64,
                )
                .expect("valid package file spec")],
            )
            .expect("valid one-file managed manifest");
            let expected_files = vec![PackageArtifactDigest {
                relative_path: "codex.exe".to_owned(),
                expected_size: bytes.len() as u64,
                sha256: digest(&bytes),
            }];
            Self {
                source: h(directory.path().to_string_lossy().into_owned()),
                _directory: directory,
                identity,
                manifest,
                expected_files,
            }
        }

        fn recipe(&self) -> ManagedEffectRecipe {
            ManagedEffectRecipe {
                recipe_id: h(crate::PORTABLE_PACKAGE_RECIPE_ID),
                action: ManagedEnvironmentAction::Install,
                operation: ManagedEffectOperation::InstallPortableGeneration,
                source_bundle: self.source.clone(),
                source_bundle_identity: self.identity.clone(),
                target_family: h(TARGET_FAMILY),
                package_version: h(PACKAGE_VERSION),
                package_manifest: self.manifest.clone(),
                expected_files: self.expected_files.clone(),
                target_relative_path: h(crate::MANAGED_TOOLS_RELATIVE_ROOT),
                registration_identity: h("registration:codex-cli"),
                executable_relative_paths: vec![h("codex.exe")],
                fixed_arguments: Vec::new(),
                allowed_resource_changes: vec![
                    ManagedResourceChange::CreatePackageGeneration,
                    ManagedResourceChange::CreateRegistration,
                ],
                postcondition: ManagedEffectPostcondition::GenerationAndRegistrationReadBack,
                unsupported_requirements: Vec::new(),
            }
        }
    }

    #[derive(Clone)]
    struct PublicationVariant {
        snapshot_id: String,
        catalogue_origin: String,
        catalogue_revision: u64,
        approval_id: String,
        approval_owner: String,
        approval_expires_at_ms: u64,
        catalogue_expires_at_ms: Option<u64>,
        publish_catalogue: bool,
        publish_approval: bool,
        native_target_path: Option<String>,
        approved_request: ManagedEnvironmentChangeRequest,
    }

    fn managed_request() -> ManagedEnvironmentChangeRequest {
        ManagedEnvironmentChangeRequest {
            request_id: h("request:codex-cli-install"),
            requester_and_reason: h("requester:managed-change-proof"),
            action: ManagedEnvironmentAction::Install,
            target_family: h(TARGET_FAMILY),
            exact_candidate: h(PACKAGE_VERSION),
            expected_delta: h("delta:codex-cli-generation-and-registration"),
            source_assurance_refs: vec![h("evidence:codex-source")],
            affected_refs: vec![h("resource:codex-cli-registration")],
            impact_class: h("impact:portable-user-scope"),
            required_owner: h(OWNER_ID),
            rollback_plan: h("rollback:owned-generation-receipt"),
            verifier: h("readback:package-and-registration"),
            budget: h("budget:one-generation"),
            stop_condition: h("stop:on-readback-mismatch"),
        }
    }

    /// Builds a non-staging managed child through the existing signed
    /// admission fixture so terminal-state tests reuse the real sealed plan
    /// path instead of manufacturing a serialized approval or recipe.
    pub(crate) fn managed_registration_transaction_for_terminal_test(
    ) -> ManagedRegistrationTransactionFixture {
        let profile_root = TempDir::new().expect("PortableDev root anchor");
        let bundle = ManagedBundle::new();
        let mut recipe = bundle.recipe();
        recipe.action = ManagedEnvironmentAction::Register;
        recipe.operation = ManagedEffectOperation::RegisterObservedPortableGeneration;
        recipe.allowed_resource_changes = vec![ManagedResourceChange::CreateRegistration];
        recipe.postcondition = ManagedEffectPostcondition::RegistrationReadBack;

        let mut request = managed_request();
        request.action = ManagedEnvironmentAction::Register;
        let native_target_directory = TempDir::new().expect("native target executable directory");
        let native_target_bytes = planner_file("preexisting-target", true);
        let native_target_path = native_target_directory.path().join("codex.exe");
        std::fs::write(&native_target_path, &native_target_bytes)
            .expect("write native target executable fixture");
        let mut publication = variant(request.clone());
        publication.native_target_path = Some(native_target_path.to_string_lossy().into_owned());
        let native_survey = crate::survey_installation(
            &catalogue(&publication, &recipe),
            &crate::WindowsSurveyObservationSource,
            &[],
        )
        .expect("native ordered survey observes the existing target executable");
        let native_family = native_survey
            .families
            .iter()
            .find(|family| family.family_id.as_str() == TARGET_FAMILY)
            .expect("native survey covers the signed target family");
        let native_candidate = native_family
            .candidates
            .first()
            .expect("native identity stage resolves the target executable");
        request.exact_candidate = native_candidate.observed_identity.clone();
        publication.approved_request = request.clone();
        let native_identity_stage = native_family
            .stages
            .iter()
            .find(|stage| stage.stage == SurveyStage::FileVersionSignatureIdentity)
            .expect("native survey retains its file identity stage");
        let native_observation = native_identity_stage
            .observations
            .iter()
            .find(|observation| {
                observation.observed_identity.as_ref()
                    == Some(&native_candidate.observed_identity)
            })
            .expect("native survey retains the candidate's exact path and file digest");
        let native_sha256 = h(
            native_observation
                .file_version
                .as_ref()
                .and_then(|file_version| file_version.sha256.as_deref())
                .expect("native survey measured the target file SHA-256"),
        );
        let target_executable_path = native_observation.input.clone();
        let fixture = signed_admission_fixture_with_recipe(
            &profile_root,
            &recipe,
            publication,
            "managed-terminal-register",
        );
        let source = crate::WindowsSurveyObservationSource;
        let context = fixture.context();
        let accepted = admit_installation_survey_and_compile_change(&context, &source, &request)
            .expect("signed owner admission produces the exact registration carrier");
        let anchor = fixture
            .store
            .load(&fixture.transaction_id)
            .expect("read the durable root-bound anchor")
            .expect("the signed fixture retains its original transaction");
        let transaction = InstallationTransaction::new_accepted_managed_change(
            &anchor,
            &accepted,
            None,
            Vec::new(),
            Vec::new(),
        )
        .expect("construct the exact managed child through the transaction owner");
        let SignedAdmissionFixture {
            _database_directory,
            _planner_bundle,
            transaction_id,
            store,
            anchor,
            authority,
            signed_snapshot,
            observed_platform,
        } = fixture;
        ManagedRegistrationTransactionFixture {
            transaction,
            _profile_root: profile_root,
            _bundle: bundle,
            _native_target_directory: native_target_directory,
            _database_directory,
            _planner_bundle,
            publication_transaction_id: transaction_id,
            store: Some(store),
            anchor,
            authority,
            _signed_snapshot: signed_snapshot,
            observed_platform,
            request,
            accepted,
            target_executable_path,
            target_executable_sha256: native_sha256,
        }
    }

    /// Keeps the real signed catalogue, source bundle and original store alive
    /// so a Windows coordinator test can admit, execute and read back the
    /// ordinary managed registration through production seams.
    pub(crate) struct ManagedRegistrationTransactionFixture {
        pub(crate) transaction: InstallationTransaction,
        _profile_root: TempDir,
        _bundle: ManagedBundle,
        _native_target_directory: TempDir,
        _database_directory: TempDir,
        _planner_bundle: TempDir,
        publication_transaction_id: PlatformHandle,
        store: Option<RedbInstallationTransactionStore>,
        anchor: InitialConfigSnapshotTrustAnchor,
        authority: crate::VerifiedSetupBinding,
        _signed_snapshot: SignedInitialConfigSnapshot,
        observed_platform: PlatformHandle,
        request: ManagedEnvironmentChangeRequest,
        pub(crate) accepted: crate::AcceptedManagedChange,
        pub(crate) target_executable_path: PlatformHandle,
        pub(crate) target_executable_sha256: PlatformHandle,
    }

    impl ManagedRegistrationTransactionFixture {
        pub(crate) fn mutate_native_target_and_revalidate(&self) -> bool {
            let Some(store) = self.store.as_ref() else {
                return false;
            };
            let context = AcceptedCatalogueContext {
                store,
                transaction_id: &self.publication_transaction_id,
                anchor: &self.anchor,
                authority: &self.authority,
                observed_platform: &self.observed_platform,
                now_ms: crate::wall_clock_millis(),
            };
            let source = crate::WindowsSurveyObservationSource;
            if self
                .accepted
                .revalidate_for_effect(&context, &source)
                .is_err()
            {
                return false;
            }
            std::fs::write(
                self.target_executable_path.as_str(),
                planner_file("changed-preexisting-target", true),
            )
            .expect("mutate the exact preexisting executable at its observed path");
            self.accepted
                .revalidate_for_effect(&context, &source)
                .is_err()
        }

        pub(crate) fn admit_and_drive(
            &mut self,
        ) -> (
            crate::InstallationStepOutcome,
            InstallationTransaction,
            Option<crate::ManagedResourceProjection>,
        ) {
            let store = self.store.take().expect("fixture store is available once");
            let source = crate::WindowsSurveyObservationSource;
            let owner = crate::ManagedChangeOwnerContext {
                publication_transaction_id: &self.publication_transaction_id,
                anchor: &self.anchor,
                authority: &self.authority,
                observed_platform: &self.observed_platform,
            };
            let mut coordinator = WindowsInstallationCoordinator::new(store);
            let transaction_id = coordinator
                .admit_managed_change(&owner, &source, &self.request)
                .expect("production admission persists the signed managed child");
            assert_eq!(transaction_id, self.transaction.transaction_id);
            let outcome = coordinator
                .drive_managed_change_until_blocked(&owner, &source, &transaction_id)
                .expect("production coordinator completes the exact managed receipt");
            let transaction = coordinator
                .inner
                .store()
                .load(&transaction_id)
                .expect("read the completed managed child")
                .expect("the original managed child remains durable");
            let projection = coordinator
                .inner
                .store()
                .managed_resource_projection(&crate::ManagedResourceKey {
                    family_id: self.request.target_family.clone(),
                    exact_candidate: self.request.exact_candidate.clone(),
                })
                .expect("derive the resource projection from its original transaction");
            (outcome, transaction, projection)
        }
    }

    /// The exact signed source, root-bound setup transaction and two distinct
    /// owner-approved requests used by the real package Repair crash-window
    /// test. The target image is copied from Windows without being executed.
    pub(crate) struct ManagedRepairCrashFixture {
        _profile_root: TempDir,
        bundle: ManagedBundle,
        _native_target_directory: TempDir,
        _database_directory: TempDir,
        _planner_bundle: TempDir,
        publication_transaction_id: PlatformHandle,
        store: Option<RedbInstallationTransactionStore>,
        trust_anchor: InitialConfigSnapshotTrustAnchor,
        authority: crate::VerifiedSetupBinding,
        _signed_snapshot: SignedInitialConfigSnapshot,
        observed_platform: PlatformHandle,
        pub(crate) anchor: InstallationTransaction,
        pub(crate) install_request: ManagedEnvironmentChangeRequest,
        pub(crate) repair_request: ManagedEnvironmentChangeRequest,
        pub(crate) refusal_request: ManagedEnvironmentChangeRequest,
        pub(crate) accepted_install: crate::AcceptedManagedChange,
        pub(crate) accepted_repair: crate::AcceptedManagedChange,
        pub(crate) accepted_refusal: crate::AcceptedManagedChange,
    }

    impl ManagedRepairCrashFixture {
        pub(crate) fn take_store(&mut self) -> RedbInstallationTransactionStore {
            self.store.take().expect("fixture store is available once")
        }

        pub(crate) fn redb_path(&self) -> std::path::PathBuf {
            self._database_directory.path().join("installation.redb")
        }

        pub(crate) fn reopen_store(&self) -> RedbInstallationTransactionStore {
            RedbInstallationTransactionStore::open_unpublished_stage_fixture_exact_path(
                self.redb_path(),
            )
            .expect("reopen the exact original physical Redb database")
        }

        /// Reuses the fixture's original signed-publication authority while a
        /// test observes the supplied live transaction store. The authority
        /// material stays private to this fixture module.
        pub(crate) fn context<'a>(
            &'a self,
            store: &'a RedbInstallationTransactionStore,
        ) -> AcceptedCatalogueContext<'a> {
            AcceptedCatalogueContext {
                store,
                transaction_id: &self.publication_transaction_id,
                anchor: &self.trust_anchor,
                authority: &self.authority,
                observed_platform: &self.observed_platform,
                now_ms: crate::wall_clock_millis(),
            }
        }

        pub(crate) fn revalidate(
            &self,
            store: &RedbInstallationTransactionStore,
            accepted: &crate::AcceptedManagedChange,
        ) -> Result<(), crate::ManagedChangeAdmissionError> {
            let context = AcceptedCatalogueContext {
                store,
                transaction_id: &self.publication_transaction_id,
                anchor: &self.trust_anchor,
                authority: &self.authority,
                observed_platform: &self.observed_platform,
                now_ms: crate::wall_clock_millis(),
            };
            accepted.revalidate_for_effect(&context, &crate::WindowsSurveyObservationSource)
        }

        pub(crate) fn install_transaction(
            &self,
        ) -> Result<InstallationTransaction, InstallationError> {
            InstallationTransaction::new_accepted_managed_change(
                &self.anchor,
                &self.accepted_install,
                None,
                Vec::new(),
                Vec::new(),
            )
        }

        pub(crate) fn repair_transaction(
            &self,
            store: &RedbInstallationTransactionStore,
        ) -> Result<InstallationTransaction, InstallationError> {
            self.transaction_for_change(
                store,
                &self.accepted_repair,
                &self.repair_request,
            )
        }

        pub(crate) fn refusal_transaction(
            &self,
            store: &RedbInstallationTransactionStore,
        ) -> Result<InstallationTransaction, InstallationError> {
            self.transaction_for_change(
                store,
                &self.accepted_refusal,
                &self.refusal_request,
            )
        }

        fn transaction_for_change(
            &self,
            store: &RedbInstallationTransactionStore,
            accepted: &crate::AcceptedManagedChange,
            request: &ManagedEnvironmentChangeRequest,
        ) -> Result<InstallationTransaction, InstallationError> {
            let key = crate::ManagedResourceKey {
                family_id: request.target_family.clone(),
                exact_candidate: request.exact_candidate.clone(),
            };
            let prior_resource = store
                .managed_resource_projection(&key)?
                .ok_or(InstallationError::IdentityConflict)?;
            let mut prior_receipts = Vec::new();
            for generation in &prior_resource.owned_generations {
                let original = store
                    .load(&generation.transaction_id)?
                    .ok_or(InstallationError::IdentityConflict)?;
                original.validate()?;
                let receipt = crate::managed_change_execution::resolve_applied_managed_effect(
                    &[original], generation,
                )?
                .ok_or(InstallationError::IdentityConflict)?;
                prior_receipts.push(receipt);
            }

            let installation_root = &self
                .anchor
                .candidate_manifest
                .runtime_launch
                .runtime_state_roots
                .installation_root;
            let tools = accepted.managed_tools_root();
            let family = tools.join(request.target_family.as_str());
            let mut prior_root_effects = Vec::new();
            for path in [tools.to_path_buf(), family] {
                let root = PlatformHandle::new(path.to_string_lossy().into_owned()).map_err(
                    |error| InstallationError::InvalidField {
                        field: "managed_root.root".to_owned(),
                        reason: error.to_string(),
                    },
                )?;
                prior_root_effects.push(
                    store
                        .managed_root_effect_proof(
                            &self.publication_transaction_id,
                            installation_root,
                            InstallationProfile::PortableDev,
                            &root,
                        )?
                        .ok_or(InstallationError::IdentityConflict)?,
                );
            }
            InstallationTransaction::new_accepted_managed_change(
                &self.anchor,
                accepted,
                Some(prior_resource),
                prior_receipts,
                prior_root_effects,
            )
        }

        pub(crate) fn package_generation_path(&self) -> std::path::PathBuf {
            self.accepted_repair
                .managed_tools_root()
                .join(&self.accepted_repair.recipe().package_manifest.generation)
        }

        pub(crate) fn source_executable_path(&self) -> std::path::PathBuf {
            Path::new(self.bundle.source.as_str()).join("codex.exe")
        }
    }

    impl Drop for ManagedRepairCrashFixture {
        fn drop(&mut self) {
            drop(self.store.take());
        }
    }

    /// Creates both approvals from the existing physical signed-publication
    /// fixture, then recompiles them through the ordinary native survey path.
    pub(crate) fn managed_repair_crash_fixture() -> ManagedRepairCrashFixture {
        managed_repair_crash_fixture_with_prior_image(None)
    }

    /// The caller may supply another already-present native image for the
    /// pre-change observation before the signed snapshot and plan are made.
    /// Package staging still uses the fixture's signed `where.exe` source.
    pub(crate) fn managed_repair_crash_fixture_with_prior_image(
        prior_image: Option<&[u8]>,
    ) -> ManagedRepairCrashFixture {
        let profile_root = TempDir::new().expect("PortableDev root anchor");
        let bundle = ManagedBundle::new_system_signed_image();
        let native_target_directory =
            TempDir::new().expect("native pre-change target directory");
        let target_bytes = match prior_image {
            Some(bytes) => bytes.to_vec(),
            None => std::fs::read(Path::new(bundle.source.as_str()).join("codex.exe"))
                .expect("read the copied signed package source image"),
        };
        let target_executable_path = native_target_directory.path().join("codex.exe");
        std::fs::write(&target_executable_path, &target_bytes)
            .expect("copy the signed image to the exact native survey target");

        let install_recipe = bundle.recipe();
        let mut repair_recipe = install_recipe.clone();
        repair_recipe.action = ManagedEnvironmentAction::Repair;
        repair_recipe.operation = ManagedEffectOperation::RepairPortableGeneration;
        repair_recipe.allowed_resource_changes = vec![ManagedResourceChange::RepairPackageGeneration];
        repair_recipe.postcondition = ManagedEffectPostcondition::GenerationRepairedReadBack;

        let mut install_request = managed_request();
        install_request.request_id = h("request:managed-repair-lost-ack-install");
        let mut repair_request = install_request.clone();
        repair_request.request_id = h("request:managed-repair-lost-ack-repair");
        repair_request.action = ManagedEnvironmentAction::Repair;
        let mut refusal_request = repair_request.clone();
        refusal_request.request_id = h("request:managed-repair-unprovable-prior");

        let mut publication = variant(install_request.clone());
        publication.approval_id = "approval:managed-repair-lost-ack-install".to_owned();
        publication.native_target_path =
            Some(target_executable_path.to_string_lossy().into_owned());
        let survey = survey_installation(
            &catalogue_with_recipes(
                &publication,
                &[install_recipe.clone(), repair_recipe.clone()],
            ),
            &crate::WindowsSurveyObservationSource,
            &[],
        )
        .expect("the actual Windows image participates in the ordered native survey");
        let family = survey
            .families
            .iter()
            .find(|family| family.family_id == h(TARGET_FAMILY))
            .expect("signed catalogue survey retains the target family");
        let native_candidate = family
            .candidates
            .first()
            .expect("native identity stage resolves the copied signed target");
        assert_eq!(family.candidates.len(), 1, "the native target is unambiguous");
        install_request.exact_candidate = native_candidate.observed_identity.clone();
        repair_request.exact_candidate = native_candidate.observed_identity.clone();
        refusal_request.exact_candidate = native_candidate.observed_identity.clone();
        publication.approved_request = install_request.clone();

        let signed = signed_admission_fixture_with_recipes_and_approvals(
            &profile_root,
            &[install_recipe, repair_recipe],
            publication,
            &[
                (h("approval:managed-repair-lost-ack-repair"), repair_request.clone()),
                (h("approval:managed-repair-unprovable-prior"), refusal_request.clone()),
            ],
            "managed-repair-lost-ack",
        );
        let context = signed.context();
        let source = crate::WindowsSurveyObservationSource;
        let accepted_install = admit_installation_survey_and_compile_change(
            &context,
            &source,
            &install_request,
        )
        .expect("the signed install request produces its sealed accepted carrier");
        let accepted_repair = admit_installation_survey_and_compile_change(
            &context,
            &source,
            &repair_request,
        )
        .expect("the distinct signed Repair request produces its sealed accepted carrier");
        let accepted_refusal = admit_installation_survey_and_compile_change(
            &context,
            &source,
            &refusal_request,
        )
        .expect("the separate signed Repair request produces its sealed refusal-test carrier");
        let anchor = signed
            .store
            .load(&signed.transaction_id)
            .expect("load the physical root-bound setup transaction")
            .expect("the setup transaction is retained in the original Redb store");
        ManagedRepairCrashFixture {
            _profile_root: profile_root,
            bundle,
            _native_target_directory: native_target_directory,
            _database_directory: signed._database_directory,
            _planner_bundle: signed._planner_bundle,
            publication_transaction_id: signed.transaction_id,
            store: Some(signed.store),
            trust_anchor: signed.anchor,
            authority: signed.authority,
            _signed_snapshot: signed.signed_snapshot,
            observed_platform: signed.observed_platform,
            anchor,
            install_request,
            repair_request,
            refusal_request,
            accepted_install,
            accepted_repair,
            accepted_refusal,
        }
    }

    fn catalogue(
        variant: &PublicationVariant,
        recipe: &ManagedEffectRecipe,
    ) -> IntegrationDiscoveryCatalogue {
        catalogue_with_recipes(variant, std::slice::from_ref(recipe))
    }

    fn catalogue_with_recipes(
        variant: &PublicationVariant,
        recipes: &[ManagedEffectRecipe],
    ) -> IntegrationDiscoveryCatalogue {
        let entries = INTEGRATION_SEED_FAMILIES
            .iter()
            .map(|(family, category)| IntegrationDiscoveryCatalogueEntry {
                family_id: h(*family),
                category: *category,
                supported_platforms: vec![h(OBSERVED_PLATFORM)],
                known_locations: vec![h(if *family == TARGET_FAMILY {
                    variant
                        .native_target_path
                        .clone()
                        .unwrap_or_else(|| r"C:\Program Files\Codex\codex.exe".to_owned())
                } else {
                    format!(r"C:\IntegrationMetadata\{family}.json")
                })],
                safe_probes: vec![h("probe:declared-detection-only")],
                bounded_probes: Vec::new(),
                managed_surfaces: Vec::new(),
                managed_effects: if *family == TARGET_FAMILY {
                    recipes.to_vec()
                } else {
                    Vec::new()
                },
                credential_refs: Vec::new(),
                assurance_refs: vec![h("assurance:signed-source-inventory")],
                adapter_candidates: Vec::new(),
                evidence_expiry_ms: None,
                declared_dependents: Vec::new(),
            })
            .collect();
        IntegrationDiscoveryCatalogue {
            schema: h(DISCOVERY_CATALOGUE_SCHEMA),
            origin: h(variant.catalogue_origin.clone()),
            revision: variant.catalogue_revision,
            supported_platforms: vec![h(OBSERVED_PLATFORM)],
            accepted_by: h(OWNER_ID),
            expires_at_ms: variant.catalogue_expires_at_ms,
            entries,
        }
    }

    fn observation(
        milestone: SetupMilestone,
        observation_name: &str,
    ) -> SetupEffectObservation {
        SetupEffectObservation {
            effect_id: h(milestone.effect_identity()),
            evidence_refs: vec![h(format!("test:evidence:{observation_name}"))],
            observed_digest: digest(observation_name.as_bytes()),
        }
    }

    fn populate_planner_bundle(directory: &Path) {
        let kernel = planner_file("eliot-kernel.exe", true);
        let protected_snapshot_digest = crate::sha256_hex(
            format!(
                "governor-protected:{INSTALLATION_ID}:{PROFILE_GENERATION}:{}",
                crate::sha256_hex(&kernel)
            )
            .as_bytes(),
        );
        for (name, executable) in crate::package_planner::REQUIRED_PACKAGE_ROLES {
            let content = if name == "eliotd-governor.json" {
                format!(r#"{{"protected_snapshot_digest":"{protected_snapshot_digest}"}}"#)
                    .into_bytes()
            } else {
                planner_file(name, executable)
            };
            std::fs::write(directory.join(name), content)
                .expect("write constructor-planner fixture role");
        }
    }

    struct SignedAdmissionFixture {
        _database_directory: TempDir,
        _planner_bundle: TempDir,
        transaction_id: PlatformHandle,
        store: RedbInstallationTransactionStore,
        anchor: InitialConfigSnapshotTrustAnchor,
        authority: crate::VerifiedSetupBinding,
        signed_snapshot: SignedInitialConfigSnapshot,
        observed_platform: PlatformHandle,
    }

    impl SignedAdmissionFixture {
        fn context(&self) -> AcceptedCatalogueContext<'_> {
            AcceptedCatalogueContext {
                store: &self.store,
                transaction_id: &self.transaction_id,
                anchor: &self.anchor,
                authority: &self.authority,
                observed_platform: &self.observed_platform,
                now_ms: super::wall_clock_millis(),
            }
        }
    }

    fn signed_admission_fixture(
        profile_root: &TempDir,
        bundle: &ManagedBundle,
        variant: PublicationVariant,
        transaction_label: &str,
    ) -> SignedAdmissionFixture {
        let recipe = bundle.recipe();
        signed_admission_fixture_with_recipe(profile_root, &recipe, variant, transaction_label)
    }

    fn signed_admission_fixture_with_recipe(
        profile_root: &TempDir,
        recipe: &ManagedEffectRecipe,
        variant: PublicationVariant,
        transaction_label: &str,
    ) -> SignedAdmissionFixture {
        signed_admission_fixture_with_recipes_and_approvals(
            profile_root,
            std::slice::from_ref(recipe),
            variant,
            &[],
            transaction_label,
        )
    }

    fn signed_admission_fixture_with_recipes_and_approvals(
        profile_root: &TempDir,
        recipes: &[ManagedEffectRecipe],
        variant: PublicationVariant,
        additional_approvals: &[(PlatformHandle, ManagedEnvironmentChangeRequest)],
        transaction_label: &str,
    ) -> SignedAdmissionFixture {
        std::fs::create_dir_all(profile_root.path().join("host"))
            .expect("create constructor-planner host root");
        let planner_bundle = TempDir::new().expect("planner source bundle");
        populate_planner_bundle(planner_bundle.path());
        let transaction_id = h(format!("transaction:{transaction_label}"));
        let source_path = h(planner_bundle.path().to_string_lossy().into_owned());
        let transaction = GenerationPackagePlanner::plan_unbound_for_test(
            GenerationPackagePlanInput {
                transaction_id: transaction_id.clone(),
                installation_epoch: InstallationEpoch {
                    installation: h(INSTALLATION_ID),
                    lineage_id: h("lineage:managed-change-proof"),
                    sequence: 1,
                },
                profile: InstallationProfile::PortableDev,
                profile_anchor_root: h(profile_root.path().to_string_lossy().into_owned()),
                installation_key: None,
                generation: h(PROFILE_GENERATION),
                source_root: source_path.clone(),
                staging_root: source_path,
                minimum_store_available_bytes: 1,
                recovery_command: h(format!(
                    "eliot installation recover --transaction-id {transaction_label}"
                )),
                agent_bridge_source: None,
            },
        )
        .expect("existing generation planner constructs the root-bound transaction");
        let roots = transaction
            .profile_governed_roots
            .as_ref()
            .expect("planner records the I3.1 roots")
            .runtime_state_roots
            .roots_digest
            .clone();
        let database_directory = TempDir::new().expect("transaction database directory");
        let mut store = RedbInstallationTransactionStore::create_unpublished_stage_fixture_at_exact_path(
            database_directory.path().join("installation.redb"),
            &transaction,
        )
        .expect("persist only the planner-produced transaction fixture");

        let owner = h(OWNER_ID);
        let mut binding = SetupBinding::new(
            transaction_id.clone(),
            h(INSTALLATION_ID),
            InstallationProfile::PortableDev,
            roots.clone(),
            0,
            owner.clone(),
            vec![h("test:confirmed-installation-identity")],
        )
        .expect("constructor-produced milestone one");
        let first = SetupMilestone::InstallationIdentityConfirmed;
        store
            .record_setup_effect_intent(&transaction_id, first, &digest(b"setup-intent-1"))
            .expect("persist first milestone intent");
        store
            .create_setup_binding(&binding)
            .expect("persist constructor-produced first milestone");

        let keys = vec![SetupKeyReference {
            key_id: h("key-ref:managed-change-proof"),
            target_ref: h("target-ref:managed-change-proof"),
            principal_sid: h("S-1-5-21-1000"),
        }];
        for milestone in SetupMilestone::all().into_iter().skip(1).take(5) {
            let intent = digest(milestone.effect_identity().as_bytes());
            store
                .record_setup_effect_intent(&transaction_id, milestone, &intent)
                .expect("persist the exact next milestone intent");
            let expected_revision = binding.revision();
            binding
                .advance(SetupAdvanceInput {
                    milestone,
                    observation: observation(milestone, milestone.effect_identity()),
                    key_references: if milestone == SetupMilestone::ServiceKeysGenerated {
                        keys.clone()
                    } else {
                        Vec::new()
                    },
                    privacy_choice: (milestone == SetupMilestone::PrivacyModeSelected)
                        .then_some(PrivacyChoice::Standard),
                })
                .expect("advance through the closed setup transition table");
            store
                .compare_and_save_setup_binding(expected_revision, &binding)
                .expect("persist the revision-checked setup result");
        }
        assert_eq!(binding.revision(), 6);

        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("fixed valid test lineage"),
            NonZeroU64::new(1).expect("non-zero test epoch"),
        )
        .expect("test authority epoch");
        let identity = InitialSnapshotIdentity {
            snapshot_id: variant.snapshot_id.clone(),
            installation_id: INSTALLATION_ID.to_owned(),
            profile_ref: crate::setup_binding::profile_ref(InstallationProfile::PortableDev)
                .expect("existing profile identity"),
            owner_ref: owner.as_str().to_owned(),
            key_identity: owner.as_str().to_owned(),
            machine_id: "machine:managed-change-proof".to_owned(),
            scope_id: "scope:managed-change-proof".to_owned(),
            runtime_state_roots_digest: roots.as_str().to_owned(),
            setup_revision: 7,
            state_fence: StateFence::new(
                epoch,
                ResourceGeneration::new(1).expect("non-zero resource generation"),
            ),
        };
        let mut payload = prepare_initial_snapshot_payload(
            &identity,
            PrivacyChoice::Standard,
            &FirstRunDecision::defaults(),
        )
        .expect("production first-run snapshot producer");
        let accepted_catalogue = catalogue_with_recipes(&variant, recipes);
        let approval = ManagedChangeApproval {
            approval_id: h(variant.approval_id.clone()),
            request: variant.approved_request.clone(),
            catalogue_origin: h(variant.catalogue_origin.clone()),
            catalogue_revision: variant.catalogue_revision,
            approved_by: h(variant.approval_owner.clone()),
            profile: InstallationProfile::PortableDev,
            runtime_state_roots_digest: roots.clone(),
            setup_revision: 7,
            snapshot_id: h(variant.snapshot_id.clone()),
            expires_at_ms: variant.approval_expires_at_ms,
        };
        let mut approvals = vec![approval];
        approvals.extend(additional_approvals.iter().map(|(approval_id, request)| {
            ManagedChangeApproval {
                approval_id: approval_id.clone(),
                request: request.clone(),
                catalogue_origin: h(variant.catalogue_origin.clone()),
                catalogue_revision: variant.catalogue_revision,
                approved_by: h(variant.approval_owner.clone()),
                profile: InstallationProfile::PortableDev,
                runtime_state_roots_digest: roots.clone(),
                setup_revision: 7,
                snapshot_id: h(variant.snapshot_id.clone()),
                expires_at_ms: variant.approval_expires_at_ms,
            }
        }));
        approvals.sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
        let approval_set = ManagedChangeApprovalSet {
            schema: h(MANAGED_CHANGE_APPROVALS_SCHEMA),
            approvals,
        };
        if variant.publish_catalogue {
            payload.snapshot.settings.push(Setting {
                key: DISCOVERY_CATALOGUE_SETTING_KEY.to_owned(),
                value_ref: format!(
                    "{LITERAL_VALUE_PREFIX}{}",
                    serde_json::to_string(&accepted_catalogue).expect("catalogue JSON")
                ),
                owner_ref: owner.as_str().to_owned(),
            });
        }
        if variant.publish_approval {
            payload.snapshot.settings.push(Setting {
                key: MANAGED_CHANGE_APPROVALS_SETTING_KEY.to_owned(),
                value_ref: format!(
                    "{LITERAL_VALUE_PREFIX}{}",
                    serde_json::to_string(&approval_set).expect("approval JSON")
                ),
                owner_ref: owner.as_str().to_owned(),
            });
        }
        payload.snapshot_canonical_sha256 = crate::sha256_hex(
            &crate::canonical_json_bytes(&payload.snapshot).expect("canonical signed settings"),
        );
        payload.validate().expect("full production payload validation");

        let signer = Ed25519InitialSnapshotSigner::from_secret_key(
            OWNER_ID,
            "test-only-managed-change-key",
            [0x42; ed25519_dalek::SECRET_KEY_LENGTH],
        )
        .expect("real Ed25519 test signer");
        let anchor = InitialConfigSnapshotTrustAnchor::new(
            INSTALLATION_ID,
            OWNER_ID,
            "test-only-managed-change-key",
            signer.public_key().to_vec(),
        )
        .expect("independently constructed public trust anchor");
        let signed_snapshot = SignedInitialConfigSnapshot::sign(&payload, &signer)
            .expect("sign the actual catalogue and approval settings");
        let snapshot_ref = h(
            signed_snapshot
                .envelope_digest()
                .expect("signed envelope digest"),
        );
        let final_milestone = SetupMilestone::InitialSnapshotCreated;
        store
            .record_setup_effect_intent(
                &transaction_id,
                final_milestone,
                &digest(final_milestone.effect_identity().as_bytes()),
            )
            .expect("persist initial-snapshot intent before its result");
        store
            .create_initial_snapshot(&transaction_id, &signed_snapshot)
            .expect("persist the actual signed snapshot via the setup owner");
        let expected_revision = binding.revision();
        binding
            .advance(SetupAdvanceInput {
                milestone: final_milestone,
                observation: SetupEffectObservation {
                    effect_id: h(final_milestone.effect_identity()),
                    evidence_refs: vec![h("test:evidence:signed-initial-snapshot")],
                    observed_digest: snapshot_ref,
                },
                key_references: Vec::new(),
                privacy_choice: None,
            })
            .expect("complete ordered snapshot milestone");
        store
            .compare_and_save_setup_binding(expected_revision, &binding)
            .expect("persist final setup revision");

        let retained_snapshot = store
            .load_initial_snapshot(&transaction_id)
            .expect("read retained signed snapshot")
            .expect("snapshot is retained");
        let retained_binding = store
            .load_setup_binding(&transaction_id)
            .expect("read persisted setup binding")
            .expect("complete setup binding is retained");
        let authority = verify_setup_binding(&retained_binding, &retained_snapshot, &anchor)
            .expect("production trust-anchor verification admits setup");
        SignedAdmissionFixture {
            _database_directory: database_directory,
            _planner_bundle: planner_bundle,
            transaction_id,
            store,
            anchor,
            authority,
            signed_snapshot,
            observed_platform: h(OBSERVED_PLATFORM),
        }
    }

    #[derive(Clone)]
    struct FixedObservationSource {
        target_identity: PlatformHandle,
    }

    impl observation_source_sealed::Sealed for FixedObservationSource {}

    impl SurveyObservationSource for FixedObservationSource {
        fn observe_known_config_or_manifest(
            &self,
            entry: &IntegrationDiscoveryCatalogueEntry,
        ) -> Result<Vec<SurveyInputObservation>, InstallationError> {
            Ok(entry
                .known_locations
                .iter()
                .cloned()
                .map(|input| SurveyInputObservation {
                    input,
                    outcome: SurveyStageOutcome::NotFound,
                    observed_identity: None,
                    evidence: None,
                    file_version: None,
                })
                .collect())
        }

        fn observe_path_metadata(
            &self,
            entry: &IntegrationDiscoveryCatalogueEntry,
        ) -> Result<Vec<SurveyInputObservation>, InstallationError> {
            self.observe_known_config_or_manifest(entry)
        }

        fn observe_file_identity(
            &self,
            entry: &IntegrationDiscoveryCatalogueEntry,
        ) -> Result<Vec<SurveyInputObservation>, InstallationError> {
            Ok(entry
                .known_locations
                .iter()
                .cloned()
                .map(|input| {
                    if entry.family_id.as_str() == TARGET_FAMILY {
                        SurveyInputObservation {
                            input,
                            outcome: SurveyStageOutcome::Found,
                            observed_identity: Some(self.target_identity.clone()),
                            evidence: Some(h("test:evidence:exact-file-identity")),
                            file_version: None,
                        }
                    } else {
                        SurveyInputObservation {
                            input,
                            outcome: SurveyStageOutcome::NotFound,
                            observed_identity: None,
                            evidence: None,
                            file_version: None,
                        }
                    }
                })
                .collect())
        }
    }

    struct CoverageObservationSource;

    impl observation_source_sealed::Sealed for CoverageObservationSource {}

    impl SurveyObservationSource for CoverageObservationSource {
        fn observe_known_config_or_manifest(
            &self,
            entry: &IntegrationDiscoveryCatalogueEntry,
        ) -> Result<Vec<SurveyInputObservation>, InstallationError> {
            if entry.family_id.as_str() != TARGET_FAMILY {
                return Ok(Vec::new());
            }
            Ok(vec![SurveyInputObservation {
                input: entry.known_locations[0].clone(),
                outcome: SurveyStageOutcome::Denied,
                observed_identity: None,
                evidence: Some(h("test:evidence:denied-known-location")),
                file_version: None,
            }])
        }

        fn observe_path_metadata(
            &self,
            entry: &IntegrationDiscoveryCatalogueEntry,
        ) -> Result<Vec<SurveyInputObservation>, InstallationError> {
            if entry.family_id.as_str() != TARGET_FAMILY {
                return Ok(Vec::new());
            }
            Ok(vec![
                SurveyInputObservation {
                    input: entry.known_locations[0].clone(),
                    outcome: SurveyStageOutcome::Unreadable,
                    observed_identity: None,
                    evidence: Some(h("test:evidence:unreadable-path-metadata")),
                    file_version: None,
                },
                SurveyInputObservation {
                    input: entry.known_locations[1].clone(),
                    outcome: SurveyStageOutcome::Invalid,
                    observed_identity: None,
                    evidence: Some(h("test:evidence:invalid-version-resource")),
                    file_version: Some(eliot_platform_windows::FileVersionObservation {
                        file_identity: None,
                        sha256: None,
                        outcome: eliot_platform_windows::FileVersionOutcome::Invalid,
                    }),
                },
            ])
        }

        fn observe_file_identity(
            &self,
            entry: &IntegrationDiscoveryCatalogueEntry,
        ) -> Result<Vec<SurveyInputObservation>, InstallationError> {
            if entry.family_id.as_str() != TARGET_FAMILY {
                return Ok(Vec::new());
            }
            Ok(vec![
                SurveyInputObservation {
                    input: entry.known_locations[0].clone(),
                    outcome: SurveyStageOutcome::Found,
                    observed_identity: Some(h("file-id:codex-cli:volume-1:index-coverage")),
                    evidence: Some(h("test:evidence:exact-file-identity")),
                    file_version: None,
                },
                SurveyInputObservation {
                    input: entry.known_locations[1].clone(),
                    outcome: SurveyStageOutcome::Ambiguous,
                    observed_identity: None,
                    evidence: Some(h("test:evidence:ambiguous-file-identity")),
                    file_version: None,
                },
            ])
        }
    }

    fn variant(request: ManagedEnvironmentChangeRequest) -> PublicationVariant {
        PublicationVariant {
            snapshot_id: "snapshot:managed-change-proof".to_owned(),
            catalogue_origin: "catalogue:managed-change-proof".to_owned(),
            catalogue_revision: 1,
            approval_id: "approval:codex-cli-install".to_owned(),
            approval_owner: OWNER_ID.to_owned(),
            approval_expires_at_ms: u64::MAX,
            catalogue_expires_at_ms: None,
            publish_catalogue: true,
            publish_approval: true,
            native_target_path: None,
            approved_request: request,
        }
    }

    #[test]
    fn real_signed_owner_admission_freezes_plan_and_rejects_all_stale_bindings() {
        let profile_root = TempDir::new().expect("PortableDev root anchor");
        let bundle = ManagedBundle::new();
        let request = managed_request();
        let original = signed_admission_fixture(
            &profile_root,
            &bundle,
            variant(request.clone()),
            "original",
        );
        let source = FixedObservationSource {
            target_identity: h("file-id:codex-cli:volume-1:index-7"),
        };
        let original_context = original.context();
        let accepted = admit_installation_survey_and_compile_change(
            &original_context,
            &source,
            &request,
        )
        .expect("real signed publication and exact approval create the private carrier");
        assert_eq!(accepted.plan().request(), &request);
        assert_eq!(accepted.approval().snapshot_id.as_str(), original.authority.snapshot_id());
        assert_eq!(
            accepted.plan().catalogue_publication_ref().as_str(),
            original
                .signed_snapshot
                .envelope_digest()
                .expect("actual retained signed envelope")
        );
        assert!(accepted.managed_tools_root().ends_with("managed-tools"));
        accepted
            .revalidate_for_effect(&original_context, &source)
            .expect("unchanged signed approval, survey and transaction root remain current");
        let target = accepted
            .accepted_survey()
            .survey
            .families
            .iter()
            .find(|family| family.family_id.as_str() == TARGET_FAMILY)
            .and_then(|family| family.candidates.first())
            .expect("exact metadata identity is retained");
        let probe_stage = accepted
            .accepted_survey()
            .survey
            .families
            .iter()
            .find(|family| family.family_id.as_str() == TARGET_FAMILY)
            .and_then(|family| {
                family
                    .stages
                    .iter()
                    .find(|stage| stage.stage == SurveyStage::AdmittedSafeProbe)
            })
            .expect("metadata survey retains explicit probe-stage coverage");
        assert_eq!(probe_stage.outcome, SurveyStageOutcome::Withheld);
        assert_eq!(probe_stage.withheld, vec![target.observed_identity.clone()]);

        let changed_executable = FixedObservationSource {
            target_identity: h("file-id:codex-cli:volume-1:index-8"),
        };
        assert!(accepted
            .revalidate_for_effect(&original_context, &changed_executable)
            .is_err());

        let mut changed_approval_variant = variant(request.clone());
        changed_approval_variant.approval_id = "approval:codex-cli-install-reissued".to_owned();
        let changed_approval_fixture = signed_admission_fixture(
            &profile_root,
            &bundle,
            changed_approval_variant,
            "changed-approval",
        );
        assert_eq!(
            changed_approval_fixture.authority.snapshot_id(),
            original.authority.snapshot_id(),
            "a re-signed publication can retain the same canonical snapshot identity"
        );
        assert_ne!(
            changed_approval_fixture
                .signed_snapshot
                .envelope_digest()
                .expect("new actual signed envelope"),
            original
                .signed_snapshot
                .envelope_digest()
                .expect("original actual signed envelope")
        );
        let changed_approval_context = changed_approval_fixture.context();
        let changed_accepted = load_accepted_catalogue(&changed_approval_context)
            .expect("independently re-signed publication still verifies");
        let changed_approval = changed_accepted
            .require_approval(
                &request,
                &changed_approval_fixture.authority,
                crate::wall_clock_millis(),
            )
            .expect("the new signed approval is current for its publication");
        assert_ne!(changed_approval, *accepted.approval());
        assert!(accepted
            .revalidate_for_effect(&changed_approval_context, &source)
            .is_err());

        let mut changed_catalogue_variant = variant(request.clone());
        changed_catalogue_variant.catalogue_origin = "catalogue:managed-change-proof-v2".to_owned();
        changed_catalogue_variant.catalogue_revision = 2;
        let changed_catalogue_fixture = signed_admission_fixture(
            &profile_root,
            &bundle,
            changed_catalogue_variant,
            "changed-catalogue",
        );
        let changed_catalogue_context = changed_catalogue_fixture.context();
        assert_eq!(
            load_accepted_catalogue(&changed_catalogue_context)
                .expect("new signed catalogue revision verifies")
                .revision(),
            2
        );
        assert!(accepted
            .revalidate_for_effect(&changed_catalogue_context, &source)
            .is_err());

        let mut changed_snapshot_variant = variant(request.clone());
        changed_snapshot_variant.snapshot_id = "snapshot:managed-change-proof-next".to_owned();
        let changed_snapshot_fixture = signed_admission_fixture(
            &profile_root,
            &bundle,
            changed_snapshot_variant,
            "changed-snapshot-id",
        );
        assert_ne!(
            changed_snapshot_fixture.authority.snapshot_id(),
            original.authority.snapshot_id()
        );
        assert!(accepted
            .revalidate_for_effect(&changed_snapshot_fixture.context(), &source)
            .is_err());

        let changed_root = TempDir::new().expect("changed root anchor");
        let changed_root_fixture = signed_admission_fixture(
            &changed_root,
            &bundle,
            variant(request.clone()),
            "changed-root",
        );
        assert_ne!(
            changed_root_fixture.authority.runtime_state_roots_digest(),
            original.authority.runtime_state_roots_digest()
        );
        assert!(accepted
            .revalidate_for_effect(&changed_root_fixture.context(), &source)
            .is_err());

        let mut wrong_approved_request = request.clone();
        wrong_approved_request.expected_delta = h("delta:different-approved-effect");
        let wrong_approval_fixture = signed_admission_fixture(
            &profile_root,
            &bundle,
            variant(wrong_approved_request),
            "wrong-request-approval",
        );
        let wrong_context = wrong_approval_fixture.context();
        assert!(matches!(
            admit_installation_survey_and_compile_change(&wrong_context, &source, &request),
            Err(ManagedChangeAdmissionError::Approval(
                ManagedChangeApprovalError::Stale
            ))
        ));
    }

    #[test]
    fn signed_managed_plan_refuses_core_family_substitution_before_effect() {
        const CORE_OWNER_REASON: &str =
            "active core components require their side-by-side generation owner";

        let profile_root = TempDir::new().expect("PortableDev root anchor");
        let bundle = ManagedBundle::new();
        let request = managed_request();
        let original = signed_admission_fixture(
            &profile_root,
            &bundle,
            variant(request.clone()),
            "core-family-substitution",
        );
        let source = FixedObservationSource {
            target_identity: h("file-id:codex-cli:volume-1:index-7"),
        };
        let original_context = original.context();
        let accepted = admit_installation_survey_and_compile_change(
            &original_context,
            &source,
            &request,
        )
        .expect("real signed publication and exact approval create the private carrier");

        let accepted_plan = accepted.plan();
        assert_eq!(accepted_plan.family_id.as_str(), TARGET_FAMILY);
        accepted_plan
            .validate()
            .expect("the actual signed benign plan validates before substitution");

        for protected_family in [
            "surrealdb",
            "eliot_store_surreal",
            "eliot-host",
            "eliot_host",
            "eliot-kernel",
            "eliot_kernel",
            "eliot-watchdog",
            "eliot_watchdog",
        ] {
            let mut substituted_plan = accepted_plan.clone();
            substituted_plan.family_id = h(protected_family);

            assert!(matches!(
                substituted_plan.validate(),
                Err(InstallationError::ProfileViolation(reason)) if reason == CORE_OWNER_REASON
            ), "protected family {protected_family:?} must route to its side-by-side owner before effects");
        }
    }

    #[test]
    fn signed_plan_retains_exact_native_target_path_hash_and_rejects_file_drift() {
        let fixture = managed_registration_transaction_for_terminal_test();
        let (target_identity, path, sha256) = fixture
            .accepted
            .plan()
            .target_executable_observation()
            .expect("the ordered native identity stage measured this exact target file");

        assert_eq!(target_identity, &fixture.request.exact_candidate);
        assert_eq!(path, &fixture.target_executable_path);
        assert_eq!(sha256, &fixture.target_executable_sha256);
        assert_ne!(
            sha256,
            &fixture.accepted.recipe().expected_files[0].sha256,
            "the retained pre-change native digest is not the new package digest"
        );
        assert!(fixture.mutate_native_target_and_revalidate());
    }

    #[test]
    fn signed_plan_keeps_native_target_unknown_without_file_version_evidence() {
        let profile_root = TempDir::new().expect("PortableDev root anchor");
        let bundle = ManagedBundle::new();
        let mut recipe = bundle.recipe();
        recipe.action = ManagedEnvironmentAction::Register;
        recipe.operation = ManagedEffectOperation::RegisterObservedPortableGeneration;
        recipe.allowed_resource_changes = vec![ManagedResourceChange::CreateRegistration];
        recipe.postcondition = ManagedEffectPostcondition::RegistrationReadBack;

        let mut request = managed_request();
        request.action = ManagedEnvironmentAction::Register;
        request.exact_candidate = h("file-id:codex-cli:volume-1:index-unknown-version");
        let publication = variant(request.clone());
        let fixture = signed_admission_fixture_with_recipe(
            &profile_root,
            &recipe,
            publication,
            "unknown-native-target",
        );
        let source = FixedObservationSource {
            target_identity: request.exact_candidate.clone(),
        };
        let context = fixture.context();
        let accepted = admit_installation_survey_and_compile_change(&context, &source, &request)
            .expect("the signed registration request is admitted against the ordered survey");

        assert_eq!(accepted.plan().target_identity(), Some(&request.exact_candidate));
        assert_eq!(accepted.plan().target_executable_observation(), None);
    }

    #[test]
    fn accepted_catalogue_accounts_for_seed_families_independently() {
        let bundle = ManagedBundle::new();
        let mut catalogue = catalogue(&variant(managed_request()), &bundle.recipe());
        let missing = catalogue.entries.pop().expect("seed catalogue is populated");
        let missing_family = missing.family_id.as_str().to_owned();

        assert!(matches!(
            catalogue.require_seed_family_coverage(),
            Err(InstallationError::IncompleteObservation(message))
                if message.contains(&missing_family)
        ));
    }

    #[test]
    fn accepted_survey_is_ordered_deterministic_and_never_admits_unknown_probe_text() {
        let bundle = ManagedBundle::new();
        let variant = variant(managed_request());
        let mut catalogue = catalogue(&variant, &bundle.recipe());
        let source = FixedObservationSource {
            target_identity: h("file-id:codex-cli:volume-1:index-7"),
        };
        let first = survey_installation(&catalogue, &source, &[])
            .expect("metadata-only survey completes in mandatory order");
        catalogue.entries.reverse();
        let reordered = survey_installation(&catalogue, &source, &[])
            .expect("unordered catalogue input retains the same ordered meaning");

        assert_eq!(first, reordered);
        let family = first
            .families
            .iter()
            .find(|family| family.family_id.as_str() == TARGET_FAMILY)
            .expect("seed family is present");
        assert_eq!(
            family.stages.iter().map(|stage| stage.stage).collect::<Vec<_>>(),
            SurveyStage::ORDER
        );
        let candidate = family
            .candidates
            .first()
            .expect("the exact identity stage reports the candidate");
        let probe_stage = family
            .stages
            .iter()
            .find(|stage| stage.stage == SurveyStage::AdmittedSafeProbe)
            .expect("mandatory probe stage is retained");
        assert_eq!(probe_stage.outcome, SurveyStageOutcome::Withheld);
        assert_eq!(probe_stage.withheld, vec![candidate.observed_identity.clone()]);
    }

    #[test]
    fn survey_preserves_denied_unreadable_invalid_ambiguous_and_not_covered_inputs() {
        let bundle = ManagedBundle::new();
        let variant = variant(managed_request());
        let mut catalogue = catalogue(&variant, &bundle.recipe());
        let (first_location, second_location) = {
            let target = catalogue
                .entries
                .iter_mut()
                .find(|entry| entry.family_id.as_str() == TARGET_FAMILY)
                .expect("target seed family is present");
            target.known_locations = vec![
                h(r"C:\Program Files\Codex\codex-alt.exe"),
                h(r"C:\Program Files\Codex\codex.exe"),
            ];
            (
                target.known_locations[0].clone(),
                target.known_locations[1].clone(),
            )
        };

        let survey = survey_installation(&catalogue, &CoverageObservationSource, &[])
            .expect("each input outcome remains represented in the ordered survey");
        let family = survey
            .families
            .iter()
            .find(|family| family.family_id.as_str() == TARGET_FAMILY)
            .expect("target family is covered");
        let known = &family.stages[0];
        let path = &family.stages[1];
        let identity = &family.stages[2];
        assert_eq!(known.denied, vec![first_location.clone()]);
        assert_eq!(known.not_covered, vec![second_location.clone()]);
        assert_eq!(path.unreadable, vec![first_location.clone()]);
        assert_eq!(path.invalid, vec![second_location.clone()]);
        assert_eq!(
            path.observations[1]
                .file_version
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(&eliot_platform_windows::FileVersionOutcome::Invalid),
        );
        assert_eq!(identity.ambiguous, vec![second_location]);
        assert_eq!(family.candidates[0].aliases, vec![first_location]);
    }

    #[test]
    fn caller_answer_handle_is_refused_as_probe_provenance() {
        let profile_root = TempDir::new().expect("PortableDev root anchor");
        let bundle = ManagedBundle::new();
        let fixture = signed_admission_fixture(
            &profile_root,
            &bundle,
            variant(managed_request()),
            "caller-answer-refused",
        );
        let accepted = load_accepted_catalogue(&fixture.context())
            .expect("real signed publication admits the detection catalogue");
        let source = FixedObservationSource {
            target_identity: h("file-id:codex-cli:volume-1:index-7"),
        };

        assert!(matches!(
            survey_installation(
                accepted.catalogue(),
                &source,
                &[SurveyProbeAnswer {
                    family_id: h(TARGET_FAMILY),
                    observed_identity: h("file-id:codex-cli:volume-1:index-7"),
                    answer: h("answer:caller-opaque-handle"),
                }],
            ),
            Err(InstallationError::IncompleteObservation(_))
        ));
    }

    #[test]
    fn missing_signed_catalogue_and_missing_exact_approval_refuse_without_defaults() {
        let profile_root = TempDir::new().expect("PortableDev root anchor");
        let bundle = ManagedBundle::new();
        let request = managed_request();
        let mut no_catalogue = variant(request.clone());
        no_catalogue.publish_catalogue = false;
        let no_catalogue_fixture = signed_admission_fixture(
            &profile_root,
            &bundle,
            no_catalogue,
            "missing-signed-catalogue",
        );
        assert!(matches!(
            load_accepted_catalogue(&no_catalogue_fixture.context()),
            Err(CatalogueAdmissionError::NotPublished)
        ));

        let mut no_approval = variant(request.clone());
        no_approval.publish_approval = false;
        let no_approval_fixture = signed_admission_fixture(
            &profile_root,
            &bundle,
            no_approval,
            "missing-exact-approval",
        );
        let source = FixedObservationSource {
            target_identity: h("file-id:codex-cli:volume-1:index-7"),
        };
        assert!(matches!(
            admit_installation_survey_and_compile_change(
                &no_approval_fixture.context(),
                &source,
                &request,
            ),
            Err(ManagedChangeAdmissionError::Approval(
                ManagedChangeApprovalError::Missing(_)
            ))
        ));
    }

    #[test]
    fn forged_signature_in_the_retained_physical_publication_is_refused() {
        let profile_root = TempDir::new().expect("PortableDev root anchor");
        let bundle = ManagedBundle::new();
        let request = managed_request();
        let fixture = signed_admission_fixture(
            &profile_root,
            &bundle,
            variant(request.clone()),
            "forged-retained-signature",
        );
        let replace_physical_snapshot = |snapshot: &SignedInitialConfigSnapshot| {
            let database = redb::Database::open(
                fixture._database_directory.path().join("installation.redb"),
            )
            .expect("open the fixture's actual physical registry");
            let write = database
                .begin_write()
                .expect("begin one physical publication replacement");
            {
                let mut table = write
                    .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                        "initial_config_snapshots_v1",
                    ))
                    .expect("open the existing initial snapshot table");
                let snapshot_bytes = serde_json::to_vec(&serde_json::json!({
                    "wire_version": eliot_config::initial_snapshot::INITIAL_SNAPSHOT_WIRE_VERSION,
                    "snapshot": snapshot,
                }))
                .expect("encode the current physical snapshot envelope");
                table
                    .insert(fixture.transaction_id.as_str(), snapshot_bytes.as_slice())
                    .expect("replace the retained row with the signed envelope");
            }
            write
                .commit()
                .expect("commit the envelope to the fixture registry");
        };

        let mut forged_snapshot = fixture.signed_snapshot.clone();
        forged_snapshot.signature = "00".repeat(forged_snapshot.signature.len() / 2);
        forged_snapshot
            .validate()
            .expect("the forged signature is structurally valid while payload remains intact");
        replace_physical_snapshot(&forged_snapshot);

        assert!(matches!(
            load_accepted_catalogue(&fixture.context()),
            Err(CatalogueAdmissionError::Snapshot(
                InitialSnapshotError::SignatureInvalid(_)
            ))
        ));

        let mut reissued_variant = variant(request);
        reissued_variant.approval_id = "approval:codex-cli-install-reissued".to_owned();
        let reissued_fixture = signed_admission_fixture(
            &profile_root,
            &bundle,
            reissued_variant,
            "same-snapshot-new-envelope",
        );
        assert_eq!(
            reissued_fixture.authority.snapshot_id(),
            fixture.authority.snapshot_id(),
            "the replacement keeps the canonical snapshot identity"
        );
        assert_ne!(
            reissued_fixture
                .signed_snapshot
                .envelope_digest()
                .expect("reissued owner signature has a valid envelope digest"),
            fixture.authority.configuration_snapshot_ref().as_str(),
            "the newly signed envelope differs from the setup owner's exact pinned bytes"
        );
        replace_physical_snapshot(&reissued_fixture.signed_snapshot);

        assert!(matches!(
            load_accepted_catalogue(&fixture.context()),
            Err(CatalogueAdmissionError::Installation(
                InstallationError::IdentityConflict
            ))
        ));
    }

    #[test]
    fn expired_catalogue_and_expired_approval_are_refused() {
        let profile_root = TempDir::new().expect("PortableDev root anchor");
        let bundle = ManagedBundle::new();
        let request = managed_request();
        let mut expired_catalogue = variant(request.clone());
        expired_catalogue.catalogue_expires_at_ms = Some(1);
        let expired_catalogue_fixture = signed_admission_fixture(
            &profile_root,
            &bundle,
            expired_catalogue,
            "expired-catalogue",
        );
        assert!(matches!(
            load_accepted_catalogue(&expired_catalogue_fixture.context()),
            Err(CatalogueAdmissionError::Expired(1))
        ));

        let mut expired_approval = variant(request.clone());
        expired_approval.approval_expires_at_ms = 1;
        let expired_approval_fixture = signed_admission_fixture(
            &profile_root,
            &bundle,
            expired_approval,
            "expired-approval",
        );
        let source = FixedObservationSource {
            target_identity: h("file-id:codex-cli:volume-1:index-7"),
        };
        assert!(matches!(
            admit_installation_survey_and_compile_change(
                &expired_approval_fixture.context(),
                &source,
                &request,
            ),
            Err(ManagedChangeAdmissionError::Approval(
                ManagedChangeApprovalError::Expired(1)
            ))
        ));
    }

    #[test]
    fn signed_recipe_for_another_target_is_refused_before_plan_compilation() {
        let profile_root = TempDir::new().expect("PortableDev root anchor");
        let bundle = ManagedBundle::new();
        let mut forged_recipe = bundle.recipe();
        forged_recipe.target_family = h("different-family");
        forged_recipe.package_manifest = PackageManifest::new(
            format!("{}/{}", forged_recipe.target_family, forged_recipe.package_version),
            forged_recipe.package_manifest.files.clone(),
        )
        .expect("forged family recipe remains internally well-formed");
        let fixture = signed_admission_fixture_with_recipe(
            &profile_root,
            &forged_recipe,
            variant(managed_request()),
            "forged-target-recipe",
        );

        assert!(matches!(
            load_accepted_catalogue(&fixture.context()),
            Err(CatalogueAdmissionError::Installation(
                InstallationError::IdentityConflict
            ))
        ));
    }

}

#[cfg(all(test, windows))]
mod catalogue_validation_tests {
    use std::num::NonZeroU64;

    use eliot_config::initial_snapshot::{
        Ed25519InitialSnapshotSigner, InitialConfigSnapshotTrustAnchor,
        InitialSnapshotIdentity, InitialSnapshotVerificationContext,
        SignedInitialConfigSnapshot, prepare_initial_snapshot_payload_with_settings,
    };
    use eliot_config::{PrivacyChoice, Setting, first_run::FirstRunDecision};
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_platform_windows::{PackageFileSpec, PackageManifest, TrustedSourceBundle};
    use crate::{
        ManagedEffectOperation, ManagedEffectPostcondition, ManagedEnvironmentAction,
        MANAGED_TOOLS_RELATIVE_ROOT,
    };
    use tempfile::TempDir;

    use super::*;

    const TEST_INSTALLATION_ID: &str = "installation:catalogue-bounds-test";
    const TEST_OWNER_ID: &str = "owner:catalogue-bounds-test";
    const TEST_KEY_ID: &str = "setup-key:catalogue-bounds-test";

    fn h(value: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(value.into()).expect("test handle is valid")
    }

    fn detection_seed_catalogue() -> IntegrationDiscoveryCatalogue {
        let entries = INTEGRATION_SEED_FAMILIES
            .iter()
            .map(|(family, category)| IntegrationDiscoveryCatalogueEntry {
                family_id: h(*family),
                category: *category,
                supported_platforms: vec![h("platform:windows-x86_64")],
                known_locations: vec![h(format!("location:{family}"))],
                safe_probes: vec![h(format!("probe:{family}"))],
                bounded_probes: Vec::new(),
                managed_surfaces: Vec::new(),
                managed_effects: Vec::new(),
                credential_refs: Vec::new(),
                assurance_refs: vec![h("assurance:detection-only")],
                adapter_candidates: Vec::new(),
                evidence_expiry_ms: None,
                declared_dependents: Vec::new(),
            })
            .collect();

        IntegrationDiscoveryCatalogue {
            schema: h(DISCOVERY_CATALOGUE_SCHEMA),
            origin: h("catalogue-origin:bounds-test"),
            revision: 1,
            supported_platforms: vec![h("platform:windows-x86_64")],
            accepted_by: h(TEST_OWNER_ID),
            expires_at_ms: None,
            entries,
        }
    }

    /// Places the exact catalogue JSON in a System Owner-owned setting,
    /// signs the ordinary initial-snapshot envelope, verifies that envelope
    /// against an external trust anchor, and decodes the retained signed
    /// setting through the production catalogue decoder.
    fn signed_catalogue_roundtrip(
        catalogue: &IntegrationDiscoveryCatalogue,
    ) -> IntegrationDiscoveryCatalogue {
        let catalogue_json = serde_json::to_string(catalogue).expect("serialize catalogue");
        let owner_setting = Setting {
            key: DISCOVERY_CATALOGUE_SETTING_KEY.to_owned(),
            value_ref: format!("{LITERAL_VALUE_PREFIX}{catalogue_json}"),
            owner_ref: TEST_OWNER_ID.to_owned(),
        };
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("fixed valid test lineage"),
            NonZeroU64::new(1).expect("non-zero test epoch"),
        )
        .expect("test authority epoch");
        let roots_digest = "a".repeat(64);
        let identity = InitialSnapshotIdentity {
            snapshot_id: "snapshot:catalogue-bounds-test".to_owned(),
            installation_id: TEST_INSTALLATION_ID.to_owned(),
            profile_ref: "portable_dev".to_owned(),
            owner_ref: TEST_OWNER_ID.to_owned(),
            key_identity: TEST_OWNER_ID.to_owned(),
            machine_id: "machine:catalogue-bounds-test".to_owned(),
            scope_id: "scope:catalogue-bounds-test".to_owned(),
            runtime_state_roots_digest: roots_digest,
            setup_revision: 1,
            state_fence: StateFence::new(
                epoch,
                ResourceGeneration::new(1).expect("non-zero resource generation"),
            ),
        };
        let signer = Ed25519InitialSnapshotSigner::from_secret_key(
            TEST_OWNER_ID,
            TEST_KEY_ID,
            [0x42; 32],
        )
        .expect("test-only snapshot signer");
        let payload = prepare_initial_snapshot_payload_with_settings(
            &identity,
            PrivacyChoice::Standard,
            &FirstRunDecision::defaults(),
            &[owner_setting],
        )
        .expect("prepare ordinary initial snapshot");
        let signed = SignedInitialConfigSnapshot::sign(&payload, &signer)
            .expect("sign catalogue setting in initial snapshot");
        let anchor = InitialConfigSnapshotTrustAnchor::new(
            TEST_INSTALLATION_ID,
            TEST_OWNER_ID,
            TEST_KEY_ID,
            signer.public_key().to_vec(),
        )
        .expect("external test trust anchor");
        let context = InitialSnapshotVerificationContext {
            installation_id: identity.installation_id,
            profile_ref: identity.profile_ref,
            runtime_state_roots_digest: identity.runtime_state_roots_digest,
            key_identity: identity.key_identity,
            setup_revision: identity.setup_revision,
        };
        let verified = anchor
            .verify(&signed, &context)
            .expect("verify actual signed initial-snapshot envelope");
        decode_catalogue_setting(
            &verified.payload().snapshot.settings,
            &h(TEST_OWNER_ID),
        )
        .expect("decode signed catalogue setting")
        .expect("signed catalogue setting is present")
    }

    fn assert_signed_catalogue_refused(
        catalogue: &IntegrationDiscoveryCatalogue,
        expected_field: &str,
        expected_reason: &str,
    ) {
        let signed_catalogue = signed_catalogue_roundtrip(catalogue);
        match signed_catalogue.validate() {
            Err(InstallationError::InvalidField { field, reason }) => {
                assert_eq!(field, expected_field);
                assert!(
                    reason.contains(expected_reason),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected signed catalogue field refusal, got {other:?}"),
        }
    }

    #[test]
    fn signed_detection_seed_passes_bounded_catalogue_validation() {
        let signed_catalogue = signed_catalogue_roundtrip(&detection_seed_catalogue());
        signed_catalogue
            .require_seed_family_coverage()
            .expect("ordinary detection-only seed remains admissible");
    }

    #[test]
    fn signed_conflicting_probe_contracts_for_one_identity_refuse_in_either_order() {
        let version = BoundedSafeProbe {
            probe_id: h("probe:version"),
            executable_identity: h("file-identity:conflicting-probe-test"),
            behaviour: ProbeBehaviour::ReportOwnVersion,
            argument: h("--version"),
            timeout_ms: 1_000,
            max_output_bytes: 1_024,
            max_descendant_processes: 0,
            working_area: h("working-area:temporary"),
            environment_names: Vec::new(),
        };
        let mut usage = version.clone();
        usage.probe_id = h("probe:usage");
        usage.behaviour = ProbeBehaviour::ReportOwnUsage;
        usage.argument = h("--help");
        let mut catalogue = detection_seed_catalogue();
        catalogue.entries[0].bounded_probes = vec![version.clone()];
        signed_catalogue_roundtrip(&catalogue).validate()
            .expect("one exact probe contract is valid");
        for probes in [vec![version.clone(), usage.clone()], vec![usage, version]] {
            catalogue.entries[0].bounded_probes = probes;
            assert!(matches!(signed_catalogue_roundtrip(&catalogue).validate(),
                Err(InstallationError::Duplicate { kind, .. })
                    if kind == "bounded probe executable identity"));
        }
    }

    #[test]
    fn signed_over_limit_platform_and_reference_arrays_refuse_before_traversal() {
        let mut catalogue = detection_seed_catalogue();
        catalogue.supported_platforms = vec![h("platform:duplicate"); MAX_ENTRY_REFS + 1];
        assert_signed_catalogue_refused(
            &catalogue,
            "catalogue.supported_platforms",
            &MAX_ENTRY_REFS.to_string(),
        );

        let mut catalogue = detection_seed_catalogue();
        catalogue.entries[0].supported_platforms =
            vec![h("platform:duplicate"); MAX_ENTRY_REFS + 1];
        assert_signed_catalogue_refused(&catalogue, "entry", "finite catalogue field limit");

        let mut catalogue = detection_seed_catalogue();
        catalogue.entries[0].known_locations =
            vec![h("location:duplicate"); MAX_ENTRY_LOCATIONS + 1];
        assert_signed_catalogue_refused(&catalogue, "entry", "finite catalogue field limit");
    }

    #[test]
    fn signed_bounded_probe_count_refuses_before_invalid_probe_fields() {
        let invalid_probe = BoundedSafeProbe {
            probe_id: h("probe:duplicate"),
            executable_identity: h("file-identity:bounded-probe-test"),
            behaviour: ProbeBehaviour::ReportOwnVersion,
            argument: h("not-an-admitted-argument"),
            timeout_ms: 0,
            max_output_bytes: 0,
            max_descendant_processes: 1,
            working_area: h("working-area:temporary"),
            environment_names: Vec::new(),
        };
        let mut catalogue = detection_seed_catalogue();
        catalogue.entries[0].bounded_probes =
            vec![invalid_probe; MAX_ENTRY_PROBES + 1];

        assert_signed_catalogue_refused(
            &catalogue,
            "bounded_probes",
            &format!("must not exceed {MAX_ENTRY_PROBES} probes"),
        );
    }

    #[test]
    fn signed_managed_effect_count_refuses_before_invalid_recipe_fields() {
        let source_dir = TempDir::new().expect("temporary source bundle directory");
        let source = TrustedSourceBundle::open(source_dir.path())
            .expect("retain test source bundle identity");
        let invalid_recipe = ManagedEffectRecipe {
            recipe_id: h("unsupported-recipe"),
            action: ManagedEnvironmentAction::Install,
            operation: ManagedEffectOperation::InstallPortableGeneration,
            source_bundle: h(source.path().to_string_lossy().into_owned()),
            source_bundle_identity: source.identity(),
            target_family: h(INTEGRATION_SEED_FAMILIES[0].0),
            package_version: h("1.0.0"),
            package_manifest: PackageManifest::new(
                format!("{}/1.0.0", INTEGRATION_SEED_FAMILIES[0].0),
                vec![PackageFileSpec::new("codex.exe", true, 1)
                    .expect("test package file spec")],
            )
            .expect("test package manifest"),
            expected_files: Vec::new(),
            target_relative_path: h(MANAGED_TOOLS_RELATIVE_ROOT),
            registration_identity: h("registration:catalogue-bounds-test"),
            executable_relative_paths: Vec::new(),
            fixed_arguments: Vec::new(),
            allowed_resource_changes: Vec::new(),
            postcondition: ManagedEffectPostcondition::GenerationAndRegistrationReadBack,
            unsupported_requirements: Vec::new(),
        };
        let mut catalogue = detection_seed_catalogue();
        catalogue.entries[0].managed_effects = vec![invalid_recipe; 7];

        assert_signed_catalogue_refused(
            &catalogue,
            "managed_effects",
            "at most one recipe for each managed action",
        );
    }
}
