//! Passive wire projections for the original installation survey owner.
//!
//! Neither a journal locator nor this request is process or capability
//! authority. The Kernel reopens the original signed publication and native
//! working-root owner before its existing process gateway may run a probe.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{ManagedCapabilityAdvertisement, ManagedEnvironmentChangeRequest, PlatformHandle};

/// Closed operation served by the authenticated Kernel installation owner.
pub const INSTALLATION_SURVEY_PROBE_OPERATION: &str = "installation_survey_probe";

/// Exact original owner inputs; all fields remain untrusted lookup data.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationSurveyProbeRequest {
    /// Existing original installation journal; creating a replacement is forbidden.
    pub store_path: PathBuf,
    /// Original transaction that retained the signed accepted publication.
    pub publication_transaction_id: PlatformHandle,
    /// Optional original completed change whose affected runtime is being
    /// requalified. Kernel loads and validates that same-table transaction;
    /// this identifier alone conveys no previous fingerprint or authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_change_transaction_id: Option<PlatformHandle>,
    /// Existing strict request, independently joined to its exact signed approval.
    pub request: ManagedEnvironmentChangeRequest,
}

/// Closed read-only installation request carried as the structured content of
/// an ordinary admitted `eliot.observe` observation. The existing bridge owns
/// its authenticated envelope; these bytes confer no installation authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", content = "payload", deny_unknown_fields)]
pub enum InstallationSurveyObservationRequest {
    /// Resolve the original signed owner publication and bounded probe recipe.
    #[serde(rename = "installation_survey_probe")]
    Probe(InstallationSurveyProbeRequest),
}

/// Decodes only this owner's structured observation content. The caller must
/// first validate the original admitted envelope, exact tool digest and live
/// attempt; this pure decoder never authenticates caller bytes.
pub fn decode_installation_survey_observation(
    tool: &serde_json::Value,
) -> Result<Option<InstallationSurveyProbeRequest>, serde_json::Error> {
    if tool.get("name").and_then(serde_json::Value::as_str) != Some("eliot.observe")
        || tool.pointer("/arguments/kind").and_then(serde_json::Value::as_str)
            != Some("observation")
    {
        return Ok(None);
    }
    let Some(content) = tool.pointer("/arguments/content") else {
        return Ok(None);
    };
    if content.get("operation").and_then(serde_json::Value::as_str)
        != Some(INSTALLATION_SURVEY_PROBE_OPERATION)
    {
        return Ok(None);
    }
    let InstallationSurveyObservationRequest::Probe(request) =
        serde_json::from_value(content.clone())?;
    Ok(Some(request))
}

/// Owner-observed survey facts, short of bridge or production admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationSurveyProbeResult {
    /// Independently requalified facts and all remaining qualification gaps.
    pub advertisement: ManagedCapabilityAdvertisement,
    /// Image bytes observed by the ordered native file-identity stage.
    /// An absent or conflicting observation remains unknown.
    pub runtime_hash: Option<String>,
    /// Original native pre-change runtime digest, only after the completed
    /// owner's exact target path and current effect readback bind this runtime.
    /// Missing owner evidence remains unknown and cannot select restrictions.
    pub previous_runtime_hash: Option<String>,
}
