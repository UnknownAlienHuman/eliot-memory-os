//! Installation discovery identity and catalogue contracts.
//!
//! The discovery survey follows Architecture `A11.2` and Implementation
//! `I3.2`, `I3.3.1`: it records safe, detection-first recipes without turning
//! presence into admission or a catalogue into a capability registry. The
//! Windows path identity keeps runtime-root validation lexical and bounded;
//! it does not grant authority or establish external process ownership.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{InstallationError, PlatformHandle, handle, handles, text};

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
    pub safe_probes: Vec<PlatformHandle>,
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
        if self.evidence_expiry_ms == Some(0) {
            return Err(InstallationError::InvalidField {
                field: "evidence_expiry_ms".to_owned(),
                reason: "must be absent or positive".to_owned(),
            });
        }
        Ok(())
    }
}

/// Immutable ELIOT-owned discovery catalogue, not a capability registry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationDiscoveryCatalogue {
    /// Catalogue origin/provenance reference.
    pub origin: PlatformHandle,
    /// Monotonic catalogue revision.
    pub revision: u64,
    /// Versioned discovery recipes.
    pub entries: Vec<IntegrationDiscoveryCatalogueEntry>,
}

impl IntegrationDiscoveryCatalogue {
    /// Validates all entries and rejects duplicate family identities.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.origin, "catalogue.origin")?;
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "catalogue.revision".to_owned(),
                reason: "must be non-zero".to_owned(),
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
        Ok(())
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
