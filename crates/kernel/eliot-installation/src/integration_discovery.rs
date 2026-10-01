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
use super::{
    InstallationError, InstallationSurvey, ManagedEnvironmentAction,
    ManagedEnvironmentChangeRequest, PlatformHandle, RedbInstallationTransactionStore,
    StateFence, SurveyObservationSource, VerifiedSetupBinding, handle, handles, text,
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
    pub managed_surfaces: Vec<PlatformHandle>,
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
        handles(&self.supported_platforms, "supported_platforms", true)?;
        handles(&self.known_locations, "known_locations", true)?;
        handles(&self.safe_probes, "safe_probes", true)?;
        handles(&self.managed_surfaces, "managed_surfaces", false)?;
        handles(&self.credential_refs, "credential_refs", false)?;
        handles(&self.assurance_refs, "assurance_refs", true)?;
        handles(&self.adapter_candidates, "adapter_candidates", false)?;
        handles(&self.declared_dependents, "declared_dependents", false)?;
        if self.known_locations.len() > MAX_ENTRY_LOCATIONS
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
        if self.bounded_probes.len() > MAX_ENTRY_PROBES {
            return Err(InstallationError::InvalidField {
                field: "bounded_probes".to_owned(),
                reason: format!("must not exceed {MAX_ENTRY_PROBES} probes"),
            });
        }
        let mut probe_ids = BTreeSet::new();
        for probe in &self.bounded_probes {
            probe.validate()?;
            if !probe_ids.insert(probe.probe_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "bounded probe".to_owned(),
                    identity: probe.probe_id.as_str().to_owned(),
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

/// Configuration setting key for System Owner-approved managed requests.
/// Rows are carried in the same retained, signed publication as the catalogue.
pub const MANAGED_CHANGE_APPROVALS_SETTING_KEY: &str = "installation.managed_change_approvals";

/// Strict schema marker for the signed managed-change approval set.
pub const MANAGED_CHANGE_APPROVALS_SCHEMA: &str = "eliot.managed-change-approvals.v1";

/// Maximum independently approved managed changes retained with one publication.
pub const MAX_MANAGED_CHANGE_APPROVALS: usize = 256;

/// The only value prefix an inline configuration setting may carry. The
/// configuration owner already uses `literal:` for deterministic values.
pub const LITERAL_VALUE_PREFIX: &str = "literal:";

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
        handles(
            &self.supported_platforms,
            "catalogue.supported_platforms",
            true,
        )?;
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
    /// No exact signed approval row exists for the requested operation.
    #[error("managed change has no exact System Owner approval in the accepted publication")]
    ApprovalRequired,
    /// The signed approval does not bind the current accepted catalogue revision.
    #[error("managed change approval is bound to a different catalogue revision")]
    ApprovalCatalogueMismatch,
    /// The signed approval has expired against the current clock reading.
    #[error("managed change approval expired at {0} Unix milliseconds")]
    ApprovalExpired(u64),
    /// The independent installation clock could not provide a valid time.
    #[error("installation owner clock is unavailable")]
    ClockUnavailable,
}

/// One System Owner-signed approval row for one exact managed request.
///
/// The request body is carried in the same retained signed publication as the
/// catalogue. Catalogue provenance, expected target identity, expiry and the
/// exact authority fence are separately bound so the row cannot be reused
/// after drift.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedChangeApproval {
    /// Stable approval identity, distinct from the managed request identity.
    pub approval_id: PlatformHandle,
    /// Exact request body the owner approved.
    pub request: ManagedEnvironmentChangeRequest,
    /// Accepted catalogue origin this approval was reviewed against.
    pub catalogue_origin: PlatformHandle,
    /// Accepted catalogue revision this approval was reviewed against.
    pub catalogue_revision: u64,
    /// Exact observed executable identity approved for non-install actions.
    /// `Install` has no current target and therefore requires `None`.
    pub expected_identity: Option<PlatformHandle>,
    /// Authority fence the owner approved; dispatch must match it exactly.
    pub state_fence: StateFence,
    /// Expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl ManagedChangeApproval {
    fn validate(&self, owner: &PlatformHandle) -> Result<(), InstallationError> {
        handle(&self.approval_id, "managed_change_approval.approval_id")?;
        self.request.validate()?;
        handle(
            &self.catalogue_origin,
            "managed_change_approval.catalogue_origin",
        )?;
        if self.catalogue_revision == 0 || self.expires_at_ms == 0 {
            return Err(InstallationError::InvalidField {
                field: "managed_change_approval".to_owned(),
                reason: "catalogue revision and approval expiry must be positive".to_owned(),
            });
        }
        if self.approvals.len() > MAX_MANAGED_CHANGE_APPROVALS {
            return Err(InstallationError::InvalidField {
                field: "managed_change_approvals.approvals".to_owned(),
                reason: format!(
                    "must not exceed {MAX_MANAGED_CHANGE_APPROVALS} owner approvals"
                ),
            });
        }
        let expected_identity = match self.request.action {
            ManagedEnvironmentAction::Install => None,
            ManagedEnvironmentAction::Update
            | ManagedEnvironmentAction::Repair
            | ManagedEnvironmentAction::Remove
            | ManagedEnvironmentAction::Register
            | ManagedEnvironmentAction::Reconfigure => Some(&self.request.exact_candidate),
        };
        let mut role_ids = BTreeSet::new();
        if [
            &self.approval_id,
            &self.request.request_id,
            &self.request.target_family,
            &self.request.exact_candidate,
        ]
        .iter()
        .any(|identity| !role_ids.insert((*identity).clone()))
            || self.request.required_owner != *owner
            || self.expected_identity.as_ref() != expected_identity
        {
            return Err(InstallationError::IdentityConflict);
        }
        self.state_fence
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "managed_change_approval.state_fence".to_owned(),
                reason: error.to_string(),
            })?;
        Ok(())
    }

    /// Returns the distinct signed approval identity.
    #[must_use]
    pub const fn approval_id(&self) -> &PlatformHandle {
        &self.approval_id
    }

    /// Returns the owner-approved target identity, when the action has one.
    #[must_use]
    pub const fn expected_identity(&self) -> Option<&PlatformHandle> {
        self.expected_identity.as_ref()
    }

    /// Returns the exact state fence the owner approved.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the approval expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

/// System Owner-owned approval set retained in the signed configuration
/// publication. Duplicate approval and request identities are refused.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedChangeApprovalSet {
    schema: PlatformHandle,
    approvals: Vec<ManagedChangeApproval>,
}

impl ManagedChangeApprovalSet {
    fn validate(&self, owner: &PlatformHandle) -> Result<(), InstallationError> {
        if self.schema.as_str() != MANAGED_CHANGE_APPROVALS_SCHEMA {
            return Err(InstallationError::MigrationRequired {
                reason: "managed change approval set schema requires explicit migration"
                    .to_owned(),
            });
        }
        let mut requests = BTreeSet::new();
        let mut approval_ids = BTreeSet::new();
        for approval in &self.approvals {
            approval.validate(owner)?;
            if !requests.insert(approval.request.request_id.clone())
                || !approval_ids.insert(approval.approval_id.clone())
            {
                return Err(InstallationError::Duplicate {
                    kind: "managed change approval".to_owned(),
                    identity: approval.request.request_id.as_str().to_owned(),
                });
            }
        }
        if requests.iter().any(|request_id| approval_ids.contains(request_id)) {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
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
    managed_approvals: Vec<ManagedChangeApproval>,
    accepted_at_ms: u64,
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

    /// Returns the exact System Owner-signed approval for `request`.
    ///
    /// The approval row comes from the same verified retained publication as
    /// this catalogue. The full request is compared with the separately
    /// retained approved request, and the row must still be live for this
    /// accepted revision and clock reading.
    pub fn approval_for(
        &self,
        request: &ManagedEnvironmentChangeRequest,
    ) -> Result<&ManagedChangeApproval, CatalogueAdmissionError> {
        let approval = self
            .managed_approvals
            .iter()
            .find(|approval| approval.request.request_id == request.request_id)
            .ok_or(CatalogueAdmissionError::ApprovalRequired)?;
        if approval.request != *request {
            return Err(CatalogueAdmissionError::ApprovalRequired);
        }
        if approval.catalogue_origin != self.catalogue.origin
            || approval.catalogue_revision != self.catalogue.revision
        {
            return Err(CatalogueAdmissionError::ApprovalCatalogueMismatch);
        }
        let now_ms = super::wall_clock_millis();
        if now_ms == 0 {
            return Err(CatalogueAdmissionError::ClockUnavailable);
        }
        if let Some(expires_at_ms) = self.catalogue.expires_at_ms
            && now_ms >= expires_at_ms
        {
            return Err(CatalogueAdmissionError::Expired(expires_at_ms));
        }
        if now_ms >= approval.expires_at_ms {
            return Err(CatalogueAdmissionError::ApprovalExpired(
                approval.expires_at_ms,
            ));
        }
        Ok(approval)
    }

    /// Returns the independent clock observation at which this retained
    /// publication was accepted.
    #[must_use]
    pub const fn accepted_at_ms(&self) -> u64 {
        self.accepted_at_ms
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
}

/// The exact installation, publication, authority and platform one accepted
/// catalogue revision is resolved against. Time is read independently from
/// the installation owner's clock and is not caller-controlled.
///
/// These five values travel together at every level of the accepted-catalogue
/// path, so they are grouped here to bind the load, the survey and the compiled
/// plan to *one* admission context by construction rather than by six separate
/// arguments a caller could pair inconsistently.
///
/// The grouping is a naming change and admits nothing on its own. This context
/// carries the installation's own durable store, the transaction whose retained
/// publication is read, the installation-pinned anchor those retained bytes are
/// verified against, the already-admitted authority whose confirmed owner must
/// have signed them, and the platform the installation was actually observed
/// on. Every admission rule still lives in
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
/// The third element is the requalified capability advertisement: the only value
/// here a consumer may present as "what is true about this candidate now". It is
/// derived from a second, independent re-derivation of the accepted catalogue
/// and the ordered survey, never from the plan's own fields, so a consumer that
/// displays a capability from this function's product is displaying a re-proof
/// and not a stored record. A plan whose bindings no longer hold is refused
/// here rather than returned.
///
/// # Errors
/// Returns [`ManagedChangeAdmissionError`] when no accepted revision loads for
/// the observed platform, when the survey or catalogue refuses, when the
/// request cannot be compiled against that exact survey and approval, or when
/// the compiled plan does not survive live requalification.
pub fn admit_installation_survey_and_compile_change(
    context: &AcceptedCatalogueContext<'_>,
    source: &dyn SurveyObservationSource,
    request: &super::ManagedEnvironmentChangeRequest,
) -> Result<
    (
        AcceptedInstallationSurvey,
        super::ManagedEnvironmentChangePlan,
        super::ManagedCapabilityAdvertisement,
    ),
    ManagedChangeAdmissionError,
> {
    let admitted = survey_accepted_installation(context, source)?;
    let plan = super::compile_managed_change_plan(
        request,
        &admitted.accepted,
        &admitted.survey,
        context.authority,
    )?;
    // Requalify before this plan is handed out, and hand the advertisement out
    // with it. A compiled plan is a record of a check performed at plan time,
    // so returning it as the only product would let a consumer read its bindings
    // and advertise on their strength — a remembered qualification. The
    // requalifier re-derives the accepted catalogue and re-runs the ordered
    // survey from the retained signed publication and the pinned anchor, so the
    // advertisement is a live re-proof. The plan still narrows to one family and
    // one exact identity and still supplies no fact about them.
    let advertisement = super::requalify_managed_capability(&plan, context, source)?;
    Ok((admitted, plan, advertisement))
}

/// Production metadata-only caller for one accepted local-host installation.
///
/// This entry point owns construction of the sealed platform observer; callers
/// cannot substitute an implementation that asserts arbitrary sightings.
/// # Errors
/// Returns the same typed catalogue or survey refusal as the underlying
/// accepted-survey path.
pub fn survey_accepted_installation_on_host(
    context: &AcceptedCatalogueContext<'_>,
) -> Result<AcceptedInstallationSurvey, CatalogueAdmissionError> {
    let source = super::WindowsSurveyObservationSource;
    survey_accepted_installation(context, &source)
}

/// Production request-to-plan caller for one accepted local-host installation.
///
/// The observer is created inside the installation owner, the approval is
/// loaded from the retained signed publication, and capability requalification
/// consumes a second survey from the same sealed source.
/// # Errors
/// Returns the same typed catalogue, approval, survey, or plan refusal as the
/// underlying admission chain.
pub fn admit_installation_survey_and_compile_change_on_host(
    context: &AcceptedCatalogueContext<'_>,
    request: &super::ManagedEnvironmentChangeRequest,
) -> Result<
    (
        AcceptedInstallationSurvey,
        super::ManagedEnvironmentChangePlan,
        super::ManagedCapabilityAdvertisement,
    ),
    ManagedChangeAdmissionError,
> {
    let source = super::WindowsSurveyObservationSource;
    admit_installation_survey_and_compile_change(context, &source, request)
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
    /// Returns the exact accepted catalogue revision behind this survey.
    #[must_use]
    pub const fn accepted(&self) -> &AcceptedIntegrationCatalogue {
        &self.accepted
    }

    /// Returns the ordered survey produced by the sealed observation source.
    #[must_use]
    pub const fn survey(&self) -> &InstallationSurvey {
        &self.survey
    }

    /// Returns the recipes resolved from observed identities, without
    /// authorizing their execution.
    #[must_use]
    pub fn admitted_probes(&self) -> &[BoundedProbeInvocation] {
        &self.admitted_probes
    }
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
/// 4. the catalogue is not expired against the installation owner's current
///    clock reading. Callers cannot select the time used for expiry.
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
    let now_ms = super::wall_clock_millis();
    if now_ms == 0 {
        return Err(CatalogueAdmissionError::ClockUnavailable);
    }
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
    let managed_approvals = decode_managed_approvals_setting(
        verified.payload().snapshot.settings.as_slice(),
        context.authority.confirmed_owner(),
    )?;
    if managed_approvals.iter().any(|approval| {
        approval.catalogue_origin != catalogue.origin
            || approval.catalogue_revision != catalogue.revision
    }) {
        return Err(CatalogueAdmissionError::ApprovalCatalogueMismatch);
    }
    if let Some(expires_at_ms) = catalogue.expires_at_ms
        && now_ms >= expires_at_ms
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
        managed_approvals,
        accepted_at_ms: now_ms,
        catalogue,
    })
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

/// Decodes exact managed-change approvals from the same retained signed
/// publication that carries the accepted catalogue.
fn decode_managed_approvals_setting(
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
            reason: "must carry a literal approval payload".to_owned(),
        }
        .into());
    };
    let approvals: ManagedChangeApprovalSet =
        serde_json::from_str(literal).map_err(|error| InstallationError::InvalidField {
            field: MANAGED_CHANGE_APPROVALS_SETTING_KEY.to_owned(),
            reason: format!("approval payload is not the current strict shape: {error}"),
        })?;
    approvals.validate(confirmed_owner)?;
    Ok(approvals.approvals)
}
