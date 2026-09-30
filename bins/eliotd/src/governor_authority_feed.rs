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
    let authority = composition
        .governor_authority_mut()
        .map_err(|error| match error {
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
    let authority = composition
        .governor_authority_mut()
        .map_err(|error| match error {
            DaemonError::Composition(error) => error,
            error => CompositionError::Recovery(error.to_string()),
        })?;
    let (projection, revoked) = authority
        .report_route_mismatch(expected_fingerprint, observed_fingerprint)
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    let revision = publish_projection(kernel, &projection).await?;
    Ok((revision, revoked))
}

/// Owner-issued observation bundle for one Governor authority feed pass
/// (issue #1935 AUD1, I7.16).
///
/// The three inputs arrive as one named bundle threaded from live
/// host/adapter, Watchdog, and trace observation owners; they are never
/// synthesized here. On this base no production owner issues the bundle yet
/// (STITCH: a verified [`IntegrationCoverageProfile`] for the exact active
/// host/adapter fingerprint, typed [`WatchdogEvidence`], and
/// [`TraceFreshness`] each need a production observation owner — the coverage
/// crate's `candidate`/`verify` constructors are reached only by tests), so
/// the daemon driver presents `None` and the first publish stays pending
/// while every Material/Critical gate refuses closed.
pub struct GovernorAuthorityObservation<'a> {
    /// Exact active-fingerprint coverage as verified production observation.
    pub coverage: &'a IntegrationCoverageProfile,
    /// Watchdog supervision evidence: an input, never a substitute grade.
    pub watchdog: &'a WatchdogEvidence,
    /// Trace freshness at derivation time.
    pub trace: TraceFreshness,
}

/// Typed outcome of one daemon-side Governor authority drive pass (issue
/// #1935 AUD1).
///
/// Skips are normal steady-state results, never errors: with no
/// owner-issued observation there is nothing to publish, with no recorded
/// baseline there is no route to compare, and an unchanged route
/// re-publishes nothing. Only a Kernel-recorded publish advances the
/// revision the gates read.
pub enum GovernorAuthorityDriveOutcome {
    /// The feed derived and the Kernel recorded `revision`.
    FeedPublished { revision: u64 },
    /// The route mismatch derived and the Kernel recorded `revision`,
    /// revoking every capability id in `revoked`.
    RouteMismatchPublished { revision: u64, revoked: Vec<String> },
    /// No owner-issued observation exists, so nothing was published.
    SkippedNoObservation,
    /// No revision was recorded yet, so there is no route to compare.
    SkippedNoBaseline,
    /// The live route still names the recorded fingerprint.
    SkippedNoChange,
}

/// Daemon-side driver for the single live Governor-owned derivation instance
/// (issue #1935 AUD1, I7.16).
///
/// Retains the exact fingerprint and revision of the last Kernel-recorded
/// publish, so a later live route observation that no longer names that
/// fingerprint drives the degraded mismatch revision that revokes everything
/// issued under the old one. The driver holds no observation of its own: the
/// feed arm publishes only caller-presented owner-issued observation, and the
/// mismatch arm compares only the recorded baseline against the
/// caller-presented live route. Constructed once per daemon run loop and
/// travels with its drive flight, exactly like the owner-feed trigger.
pub struct GovernorAuthorityDriver {
    last_published: Option<(String, u64)>,
}

impl GovernorAuthorityDriver {
    /// Starts with no recorded publish: nothing is authorized until the first
    /// feed publish records, and no route comparison runs until then.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_published: None,
        }
    }

    /// Drives one feed pass through the designated
    /// [`maintain_governor_authority_feed`] driver and records its baseline.
    ///
    /// With no owner-issued observation the pass skips without touching the
    /// composition or the Kernel: the first publish stays pending and the
    /// gates keep refusing closed. On a recorded publish the baseline becomes
    /// the presented coverage fingerprint at the recorded revision.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Owner`] when the presented coverage is not
    /// verified production observation or an input is invalid, and
    /// [`CompositionError::Recovery`] on transport failure or when the
    /// receipt disagrees with the projected revision.
    pub async fn drive_feed(
        &mut self,
        composition: &mut DaemonComposition,
        kernel: &Arc<DaemonKernelClient>,
        observation: Option<GovernorAuthorityObservation<'_>>,
    ) -> Result<GovernorAuthorityDriveOutcome, CompositionError> {
        let Some(observation) = observation else {
            return Ok(GovernorAuthorityDriveOutcome::SkippedNoObservation);
        };
        let revision = maintain_governor_authority_feed(
            composition,
            kernel,
            observation.coverage,
            observation.watchdog,
            observation.trace,
        )
        .await?;
        self.last_published = Some((observation.coverage.fingerprint.clone(), revision));
        Ok(GovernorAuthorityDriveOutcome::FeedPublished { revision })
    }

    /// Drives one route-mismatch pass through the designated
    /// [`maintain_governor_authority_route_mismatch`] driver and records its
    /// baseline.
    ///
    /// `live_route` is the caller-observed active route identity; the daemon
    /// runtime presents the validated Kernel-issued owner session binding
    /// (`DaemonKernelClient::owner_session_facts`), never a minted value.
    /// With no live route the pass skips; with no recorded baseline there is
    /// nothing to compare; with the live route still naming the recorded
    /// fingerprint nothing re-publishes. Otherwise the degraded revision
    /// publishes and the baseline advances to the observed route at the new
    /// revision, so the lost guarantee revokes dependent authority.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Owner`] when either fingerprint is blank,
    /// control-carrying, or the pair names no mismatch, and
    /// [`CompositionError::Recovery`] on transport failure or when the
    /// receipt disagrees with the projected revision.
    pub async fn drive_route_mismatch(
        &mut self,
        composition: &mut DaemonComposition,
        kernel: &Arc<DaemonKernelClient>,
        live_route: Option<&str>,
    ) -> Result<GovernorAuthorityDriveOutcome, CompositionError> {
        let Some(live_route) = live_route else {
            return Ok(GovernorAuthorityDriveOutcome::SkippedNoObservation);
        };
        let Some((baseline_fingerprint, _)) = self.last_published.clone() else {
            return Ok(GovernorAuthorityDriveOutcome::SkippedNoBaseline);
        };
        if live_route == baseline_fingerprint {
            return Ok(GovernorAuthorityDriveOutcome::SkippedNoChange);
        }
        let (revision, revoked) = maintain_governor_authority_route_mismatch(
            composition,
            kernel,
            &baseline_fingerprint,
            live_route,
        )
        .await?;
        self.last_published = Some((live_route.to_owned(), revision));
        Ok(GovernorAuthorityDriveOutcome::RouteMismatchPublished { revision, revoked })
    }
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
    let receipt: GovernorAuthorityReceiptWire = serde_json::from_value(value).map_err(|error| {
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
