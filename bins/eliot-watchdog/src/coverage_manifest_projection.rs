//! Projects this Watchdog owner's published interval coverage into the shared
//! `ObservationCoverageManifest` (issue #1755, W6).
//!
//! Until this module the shared contract had zero producers and zero
//! consumers: `ObservationCoverageManifest` existed in
//! `eliot-evaluation-contracts` and nothing in the workspace ever built one.
//! The Watchdog already publishes exactly the interval coverage the contract
//! binds - per channel, per expected source, per observed class, with the
//! disposition, dropped samples and named gaps - so this is a LOSS-LESS
//! PROJECTION, not a second coverage model: every field is carried from the
//! spool owner's own record and nothing is recomputed or defaulted here.
//!
//! What the projection deliberately does NOT do:
//!
//! - It does not invent a session/attempt identity. The contract's
//!   installation-level binding is used exactly as the owner resolved it.
//! - It does not change ownership. Operational cursor and high-water state stay
//!   in the Watchdog spool; this returns a read-only denominator.
//! - It does not upgrade a result. A channel that observed its subject live
//!   while the subject is absent stays `CONTINUOUS`; the health result lives in
//!   `HostObservationState`, not here.

use eliot_evaluation_contracts::{
    CoverageCompleteness, EvaluationContractError, INSTALLATION_COVERAGE_BINDING_VERSION,
    InstallationChannelCoverage, InstallationCoverageBinding, ObservationCoverageManifest,
};

use crate::observation_coverage::{ChannelIntervalCoverage, IntervalCoverageReport};

/// Projects one published interval report into the shared coverage manifest.
///
/// `binding` supplies the caller-resolved installation identity, allowed
/// manifest digest and declared window; the report supplies everything else.
/// The projection is refused rather than repaired: an invalid binding, an empty
/// report, or a record the shared contract rejects produces a typed error and
/// no manifest.
///
/// # Errors
///
/// Returns [`EvaluationContractError`] when the binding or the projected
/// channel records do not validate, or when the report carries no record.
pub fn project_interval_coverage(
    binding: &InstallationCoverageBinding,
    report: &IntervalCoverageReport,
) -> Result<ObservationCoverageManifest, EvaluationContractError> {
    if report.records().is_empty() {
        return Err(EvaluationContractError::EmptyCollection {
            field: "watchdog_coverage.records",
        });
    }
    let channels: Vec<InstallationChannelCoverage> =
        report.records().iter().map(project_channel).collect();
    ObservationCoverageManifest::for_installation_interval(binding, &channels)
}

/// Carries one spool-owned channel record into the shared contract's shape.
///
/// Field-for-field: the channel name, expected source and expected classes come
/// from the owner's capability map, the observed classes are the live samples it
/// actually recorded, and the disposition, dropped count, replay count with its
/// exact evidence, closure flag and named gap reasons are its own. A replayed
/// record projects only with the evidence the shared contract's binding
/// version 2 requires; anything else is refused by that contract's own rules.
fn project_channel(record: &ChannelIntervalCoverage) -> InstallationChannelCoverage {
    InstallationChannelCoverage {
        channel: record.channel().as_str().to_owned(),
        expected_source: record.expected_source().to_owned(),
        expected_classes: record
            .expected_classes()
            .iter()
            .map(|class| class.as_str().to_owned())
            .collect(),
        observed_classes: record
            .observed_classes()
            .iter()
            .map(|class| class.as_str().to_owned())
            .collect(),
        observed_replayed_observations: record.observed_replayed_observations(),
        replay_evidence: record.replayed_evidence().cloned(),
        dropped_samples: record.dropped_samples(),
        interval_closed: record.interval_closed(),
        disposition: record.disposition().as_str().to_owned(),
        gap_reasons: record
            .gaps()
            .iter()
            .map(|gap| gap.reason.to_owned())
            .collect(),
    }
}

/// What publishing one interval's shared coverage manifest produced.
///
/// The omitted arm is a real outcome, not a silent skip: it names exactly which
/// owner value was unavailable, so an unprojected interval is visible instead of
/// looking like a Watchdog that simply had nothing to report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageManifestOutcome {
    /// The shared manifest was produced from the owner's own report.
    Published {
        /// Completeness the shared contract derived from every channel.
        completeness: CoverageCompleteness,
        /// Per-channel streams the manifest now declares.
        streams: usize,
    },
    /// No manifest was produced, and this is why.
    Omitted(&'static str),
}

/// Projects one closed interval into the shared coverage manifest using only
/// owner-supplied identities.
///
/// `installation_identity` and `allowed_manifest_digest` both come from the
/// admitted Kernel port. When either is absent the interval is OMITTED with the
/// named missing owner: a Watchdog that cannot resolve its own allowed manifest
/// revision has no honest denominator to publish, and substituting one would put
/// a fabricated revision into an evidence record.
///
/// # Errors
///
/// Never: an unusable input is an [`CoverageManifestOutcome::Omitted`], and a
/// contract rejection is reported as such rather than propagating an error the
/// tick would have to handle.
#[must_use]
pub fn publish_interval_coverage_manifest(
    installation_identity: Option<&str>,
    allowed_manifest_digest: Option<&str>,
    report: &IntervalCoverageReport,
) -> CoverageManifestOutcome {
    let Some(installation_id) = installation_identity else {
        return CoverageManifestOutcome::Omitted("INSTALLATION_IDENTITY_UNAVAILABLE");
    };
    let Some(manifest_digest) = allowed_manifest_digest else {
        return CoverageManifestOutcome::Omitted("ALLOWED_MANIFEST_DIGEST_UNAVAILABLE");
    };
    let interval = report.interval();
    let binding = InstallationCoverageBinding {
        installation_id: installation_id.to_owned(),
        allowed_manifest_digest: manifest_digest.to_owned(),
        sensor_map_revision: report.sensor_map_revision(),
        interval_start_ms: interval.start_ms,
        interval_end_ms: interval.end_ms,
        binding_version: INSTALLATION_COVERAGE_BINDING_VERSION,
    };
    match project_interval_coverage(&binding, report) {
        Ok(manifest) => CoverageManifestOutcome::Published {
            completeness: manifest.completeness,
            streams: manifest.first_and_last_expected_cursors_by_stream.len(),
        },
        // A typed contract refusal is still an omission, never a partial
        // manifest: the shared denominator either holds or it does not.
        Err(_) => CoverageManifestOutcome::Omitted("COVERAGE_MANIFEST_CONTRACT_REFUSED"),
    }
}
#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "the projection tests build the owner's own published report; a fixture that cannot publish is a test failure"
)]
mod tests {
    use super::{
        CoverageManifestOutcome, project_interval_coverage, publish_interval_coverage_manifest,
    };
    use crate::observation_coverage::{
        IntervalCoveragePublisher, ObservationChannel, channel_capability,
    };
    use eliot_evaluation_contracts::{
        CoverageCompleteness, EvaluationContractError, INSTALLATION_COVERAGE_BINDING_VERSION,
        InstallationCoverageBinding,
    };

    fn binding() -> InstallationCoverageBinding {
        InstallationCoverageBinding {
            installation_id: "installation-1755".to_owned(),
            allowed_manifest_digest: "a".repeat(64),
            sensor_map_revision: 2,
            interval_start_ms: 1_000,
            interval_end_ms: 2_000,
            binding_version: INSTALLATION_COVERAGE_BINDING_VERSION,
        }
    }

    /// Records every class every channel declares support for, so the published
    /// report is the owner's own eleven-channel denominator rather than a
    /// single-channel fixture.
    fn fully_observed_report() -> crate::observation_coverage::IntervalCoverageReport {
        let mut publisher = IntervalCoveragePublisher::new(1_000);
        for channel in ObservationChannel::ALL {
            let capability = channel_capability(channel);
            for class in capability.supported_classes {
                publisher.record(channel, *class);
            }
        }
        publisher.close(2_000)
    }

    #[test]
    fn the_shared_contract_gains_a_real_producer_from_the_spool_owner() {
        let report = fully_observed_report();
        let manifest = project_interval_coverage(&binding(), &report)
            .expect("the owner's own report projects into the shared contract");
        assert_eq!(
            manifest.first_and_last_expected_cursors_by_stream.len(),
            report.records().len(),
            "one declared stream per published channel: the projection is per-channel, not a summary"
        );
        assert!(
            manifest
                .expected_event_sources_and_event_classes
                .iter()
                .all(|entry| entry.starts_with("watchdog:")),
            "the manifest names the Watchdog as the competent source of every class"
        );
    }

    #[test]
    fn a_channel_nothing_observed_stays_named_and_never_becomes_complete() {
        // One channel deliberately observed nothing, so the joined denominator
        // must keep it as a named gap instead of dropping or upgrading it.
        let mut publisher = IntervalCoveragePublisher::new(1_000);
        let mut silent: Option<ObservationChannel> = None;
        for channel in ObservationChannel::ALL {
            let capability = channel_capability(channel);
            if silent.is_none() && !capability.supported_classes.is_empty() {
                silent = Some(channel);
                continue;
            }
            for class in capability.supported_classes {
                publisher.record(channel, *class);
            }
        }
        let report = publisher.close(2_000);
        let manifest = project_interval_coverage(&binding(), &report)
            .expect("a partially observed interval still projects");
        assert_ne!(
            manifest.completeness,
            CoverageCompleteness::Complete,
            "an interval with an unobserved channel is not complete coverage"
        );
        assert!(
            !manifest
                .blind_intervals_and_missing_source_reasons
                .is_empty()
                || !manifest.missing_source_reasons.is_empty(),
            "the unobserved channel is retained as a named gap, not dropped"
        );
        assert!(
            silent.is_some(),
            "the fixture really did leave one channel unobserved"
        );
    }

    #[test]
    fn an_invalid_binding_is_refused_instead_of_producing_a_manifest() {
        let report = fully_observed_report();
        let mut broken = binding();
        broken.binding_version = INSTALLATION_COVERAGE_BINDING_VERSION + 1;
        let error = project_interval_coverage(&broken, &report)
            .expect_err("a non-current binding version must be refused");
        assert!(
            matches!(error, EvaluationContractError::EvidenceState { .. }),
            "the refusal is typed, got {error:?}"
        );
    }

    #[test]
    fn the_production_publisher_omits_rather_than_invents_a_missing_owner_identity() {
        let report = fully_observed_report();
        // Neither identity available: two different named omissions, and no
        // manifest in either arm.
        assert_eq!(
            publish_interval_coverage_manifest(None, None, &report),
            CoverageManifestOutcome::Omitted("INSTALLATION_IDENTITY_UNAVAILABLE"),
            "without the installation identity nothing is projected"
        );
        assert_eq!(
            publish_interval_coverage_manifest(Some("installation-1755"), None, &report),
            CoverageManifestOutcome::Omitted("ALLOWED_MANIFEST_DIGEST_UNAVAILABLE"),
            "the allowed manifest revision has a single owner and is never defaulted"
        );
        // Non-vacuity: with both owner values the same report publishes.
        match publish_interval_coverage_manifest(
            Some("installation-1755"),
            Some(&"a".repeat(64)),
            &report,
        ) {
            CoverageManifestOutcome::Published { streams, .. } => {
                assert_eq!(streams, report.records().len());
            }
            CoverageManifestOutcome::Omitted(reason) => {
                panic!("both owner identities are present, got omission {reason}");
            }
        }
    }
}
