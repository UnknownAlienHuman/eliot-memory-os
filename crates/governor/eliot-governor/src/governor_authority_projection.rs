//! Live Governor-owned coverage-to-authority projection (issue #1935 AUD1, I7.16).
//!
//! The coverage crate owns derivation mechanics
//! ([`GovernorCoverageDerivation`](eliot_integration_coverage::GovernorCoverageDerivation));
//! this module owns the single live derivation instance the Governor feeds
//! from runtime observation and the closed projection of its exact
//! revision, exact active fingerprint, and exact authorization axes across
//! the authenticated `publish_governor_authority` boundary. No third profile
//! vocabulary is introduced: the projection names the owner's
//! `GovernanceProfile::authorizes` axes exactly, and the Kernel maps them to
//! its existing three-axis profile under its strictly-advancing revision
//! rule, so a newer degraded projection revokes everything issued under the
//! old one. Watchdog evidence stays an input, never a substitute grade.

use eliot_integration_coverage::{
    CoverageError, GovernorCoverageDerivation, IntegrationCoverageProfile, TraceFreshness,
    WatchdogEvidence,
};

/// Closed projection of one live Governor derivation across the
/// authenticated boundary (issue #1935 AUD1).
///
/// `revision`/`fingerprint` name the owner binding exactly as the owner
/// names it; `verified`, `authorizes_enforcement`, and
/// `authorizes_complete_coverage_ops` name the owner's authorization axes
/// exactly. The daemon publishes this shape as the `publish_governor_authority`
/// payload and the Kernel records it under its revision rule.
///
/// The three booleans are the owner's independent authorization axes, not a
/// bool bag, so the excessive-bools lint is allowed here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernorAuthorityProjection {
    revision: u64,
    fingerprint: String,
    verified: bool,
    authorizes_enforcement: bool,
    authorizes_complete_coverage_ops: bool,
}

impl GovernorAuthorityProjection {
    /// Exact owner derivation revision this projection was issued under.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Exact active host/adapter fingerprint the owner derived for.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Whether the derived profile is verified production coverage.
    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verified
    }

    /// Whether the derived profile authorizes enforcement-dependent operations.
    #[must_use]
    pub const fn authorizes_enforcement(&self) -> bool {
        self.authorizes_enforcement
    }

    /// Whether the derived profile authorizes complete-coverage operations.
    #[must_use]
    pub const fn authorizes_complete_coverage_ops(&self) -> bool {
        self.authorizes_complete_coverage_ops
    }
}

/// The single live Governor-owned derivation instance (issue #1935 AUD1, I7.16).
///
/// Owns exactly one
/// [`GovernorCoverageDerivation`](eliot_integration_coverage::GovernorCoverageDerivation):
/// every `refresh` derives from the threaded runtime coverage, Watchdog
/// evidence, and trace freshness and projects the current owner revision;
/// every route-mismatch report derives the degraded revision that authorizes
/// nothing, so capabilities bound to the lost revision revoke. The daemon
/// composition root owns one of these for the process lifetime.
#[derive(Debug)]
pub struct LiveGovernorAuthority {
    derivation: GovernorCoverageDerivation,
}

impl LiveGovernorAuthority {
    /// Starts with no derived profile: nothing is authorized until the first
    /// `refresh` derives from live observation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            derivation: GovernorCoverageDerivation::new(),
        }
    }

    /// Derives the current profile from runtime coverage, Watchdog evidence,
    /// and trace freshness, and projects its exact revision, fingerprint,
    /// and authorization axes for the authenticated boundary.
    ///
    /// An unchanged re-derivation keeps the owner revision; any content
    /// change emits a new revision and revokes every capability the new
    /// profile no longer authorizes.
    ///
    /// # Errors
    ///
    /// Returns the owner's fail-closed reason when the coverage is not
    /// verified production observation or an input is invalid.
    pub fn refresh(
        &mut self,
        coverage: &IntegrationCoverageProfile,
        watchdog: &WatchdogEvidence,
        trace: TraceFreshness,
    ) -> Result<GovernorAuthorityProjection, CoverageError> {
        let profile = self.derivation.derive(coverage, watchdog, trace)?;
        Ok(Self::project(&profile))
    }

    /// Reports an observed route mismatch: the active route is no longer the
    /// profile fingerprint. Projects the new degraded revision that
    /// authorizes nothing and returns the capability ids the owner revoked
    /// with it.
    ///
    /// # Errors
    ///
    /// Returns the owner's fail-closed reason when either fingerprint is
    /// blank, control-carrying, or the pair names no mismatch.
    pub fn report_route_mismatch(
        &mut self,
        expected_fingerprint: &str,
        observed_fingerprint: &str,
    ) -> Result<(GovernorAuthorityProjection, Vec<String>), CoverageError> {
        let (profile, revoked) = self
            .derivation
            .report_route_mismatch(expected_fingerprint, observed_fingerprint)?;
        Ok((Self::project(&profile), revoked))
    }

    /// Projects one owner profile into the exact boundary shape.
    fn project(
        profile: &eliot_integration_coverage::GovernanceProfile,
    ) -> GovernorAuthorityProjection {
        GovernorAuthorityProjection {
            revision: profile.revision,
            fingerprint: profile.fingerprint.clone(),
            verified: profile.verified,
            authorizes_enforcement: profile.authorizes_enforcement,
            authorizes_complete_coverage_ops: profile.authorizes_complete_coverage_ops,
        }
    }
}
