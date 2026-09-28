//! Daemon publisher for the live Governor-derived authority projection
//! (issue #1935 AUD1, I7.16).
//!
//! Architecture traceability: I7.16 keeps the Governor the sole deriver of
//! the revision-bearing `GovernanceProfile` from runtime coverage, Watchdog
//! supervision evidence, and trace freshness, and revokes authority that
//! depended on a lost guarantee; I1.8 keeps the daemon/Kernel call path
//! behind the authenticated transport; A13.2 keeps daemon/Kernel failure
//! domains explicit.
//!
//! This module owns the daemon side of that path: it feeds the single live
//! Governor-owned derivation instance held by the daemon composition root
//! ([`DaemonComposition`](super::DaemonComposition)) from threaded runtime
//! observation and projects the result across the authenticated
//! `publish_governor_authority` boundary. The Kernel maps the exact
//! revision, exact active fingerprint, and exact authorization axes to its
//! existing three-axis profile under its strictly-advancing revision rule,
//! so a newer degraded projection revokes everything issued under the old
//! one. Until the first publish records, every Material/Critical gate
//! refuses closed.
//!
//! Forbidden boundary: no coverage synthesis (inputs arrive threaded from
//! live host/Watchdog/trace observation, never built here), no second
//! derivation instance, no third profile vocabulary, and no success claim
//! without the Kernel receipt proving the exact published bytes.

use std::sync::Arc;

use eliot_governor::CompositionError;
use eliot_integration_coverage::{IntegrationCoverageProfile, TraceFreshness, WatchdogEvidence};

use super::daemon_kernel_client::DaemonKernelClient;
use super::{DaemonComposition, DaemonError, kind_value};

/// Daemon->Kernel front-door governor-authority publish operation: names the
/// exact arm the Kernel dispatcher serves. The transport injects this name
/// into the payload object, so it is not duplicated there.
const PUBLISH_GOVERNOR_AUTHORITY_OPERATION: &str = "publish_governor_authority";
/// Typed receipt kind answered by the publish arm.
const GOVERNOR_AUTHORITY_RECEIPT_KIND: &str = "governor_authority_receipt";
/// Only an acknowledged `recorded` receipt counts as published.
const GOVERNOR_AUTHORITY_RECORDED_STATUS: &str = "recorded";

/// Wire shape answered by the Kernel `publish_governor_authority` arm: the
/// recorded revision plus the acknowledged status. Anything but `recorded`
/// at the projected revision is a refusal, never a partial publish.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernorAuthorityReceiptWire {
    revision: u64,
    status: String,
}

/// Derives the current Governor profile from the threaded runtime coverage,
/// Watchdog evidence, and trace freshness, and publishes its exact revision,
/// fingerprint, and authorization axes to the Kernel (`#1935` AUD1
/// designated driver).
///
/// The derivation instance is the single one owned by the composition root,
/// so a degraded re-derivation publishes a new revision that revokes
/// everything issued under the old one. Returns the recorded revision the
/// Kernel acknowledged. The daemon runtime drives this when live host
/// observation arrives; coverage is never synthesized here.
///
/// # Errors
///
/// Returns [`CompositionError::Owner`] when the coverage is not verified
/// production observation or an input is invalid, and
/// [`CompositionError::Recovery`] on transport failure or when the receipt
/// disagrees with the projected revision.
pub async fn maintain_governor_authority_feed(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    coverage: &IntegrationCoverageProfile,
    watchdog: &WatchdogEvidence,
    trace: TraceFreshness,
) -> Result<u64, CompositionError> {
    let authority = composition.governor_authority_mut().map_err(|error| match error {
        DaemonError::Composition(error) => error,
        error => CompositionError::Recovery(error.to_string()),
    })?;
    let projection = authority
        .refresh(coverage, watchdog, trace)
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    publish_projection(kernel, &projection).await
}

/// Publishes the degraded Governor revision for an observed route mismatch
/// (`#1935` AUD1 designated driver).
///
/// Returns the recorded revision plus the capability ids the owner revoked
/// with it. The daemon runtime drives this when the active route proves to
/// be no longer the profile fingerprint.
///
/// # Errors
///
/// Returns [`CompositionError::Owner`] when either fingerprint is blank,
/// control-carrying, or the pair names no mismatch, and
/// [`CompositionError::Recovery`] on transport failure or when the receipt
/// disagrees with the projected revision.
pub async fn maintain_governor_authority_route_mismatch(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    expected_fingerprint: &str,
    observed_fingerprint: &str,
) -> Result<(u64, Vec<String>), CompositionError> {
    let authority = composition.governor_authority_mut().map_err(|error| match error {
        DaemonError::Composition(error) => error,
        error => CompositionError::Recovery(error.to_string()),
    })?;
    let (projection, revoked) = authority
        .report_route_mismatch(expected_fingerprint, observed_fingerprint)
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let revision = publish_projection(kernel, &projection).await?;
    Ok((revision, revoked))
}

/// Publishes one projected revision and verifies the Kernel receipt proves
/// that exact revision.
async fn publish_projection(
    kernel: &Arc<DaemonKernelClient>,
    projection: &eliot_governor::GovernorAuthorityProjection,
) -> Result<u64, CompositionError> {
    let payload = serde_json::json!({
        "revision": projection.revision(),
        "fingerprint": projection.fingerprint(),
        "verified": projection.verified(),
        "authorizes_enforcement": projection.authorizes_enforcement(),
        "authorizes_complete_coverage_ops": projection.authorizes_complete_coverage_ops(),
    });
    let value = kernel
        .transact_async(PUBLISH_GOVERNOR_AUTHORITY_OPERATION, payload)
        .await
        .map_err(|error| {
            CompositionError::Recovery(format!("governor authority publish transport: {error}"))
        })?;
    let value = kind_value(&value, GOVERNOR_AUTHORITY_RECEIPT_KIND).map_err(|error| {
        CompositionError::Owner(format!("governor authority receipt kind: {error}"))
    })?;
    let receipt: GovernorAuthorityReceiptWire =
        serde_json::from_value(value).map_err(|error| {
            CompositionError::Owner(format!(
                "governor authority receipt does not decode: {error}"
            ))
        })?;
    if receipt.status != GOVERNOR_AUTHORITY_RECORDED_STATUS
        || receipt.revision != projection.revision()
    {
        return Err(CompositionError::Recovery(
            "governor authority receipt disagrees with the projected revision".to_owned(),
        ));
    }
    Ok(receipt.revision)
}
