//! Host-observed coverage denominators and compliance traces (issue #1936).
//!
//! This module is the evaluation-evidence owner for two I7.23 shapes:
//! [`ObservationCoverageManifest`] declares the complete denominator for one
//! product/session/attempt/route fingerprint, and
//! [`HostObservedComplianceTrace`] derives a `PASS | TAINTED | FAIL | UNKNOWN`
//! disposition only from immutable host/runtime records joined to that
//! denominator.
//!
//! A trace never upgrades incomplete observation to `PASS`: cursor gaps,
//! payload mutations, blind intervals, undeclared shell/web/filesystem/repository
//! access, hidden schema/output-file reads, out-of-namespace writes, and
//! denominator gaps yield `TAINTED` or `UNKNOWN` and name the blind interval,
//! access, or incomplete denominator. Sequence gaps and payload mutations must
//! be localized to blind intervals on the manifest; unlocalized faults are
//! rejected fail-closed. Percentages and absence-of-event claims are admissible
//! only against a declared complete denominator free of gaps and payload
//! mutations (see [`absence_claim_admissible`] and [`coverage_percentage`]).

use std::collections::BTreeSet;

use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{EvaluationContractError, text};

/// Completeness of the declared denominator for one run.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageCompleteness {
    Complete,
    Partial,
    Unknown,
    NotApplicable,
}

/// Disposition derived only from immutable host/runtime records.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComplianceDisposition {
    Pass,
    Tainted,
    Fail,
    Unknown,
}

/// Product/session/attempt/route fingerprint binding one denominator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunFingerprint {
    pub product_id: String,
    pub session_id: String,
    pub attempt_id: String,
    pub route_fingerprint: String,
}

impl RunFingerprint {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.product_id, "fingerprint.product_id")?;
        text(&self.session_id, "fingerprint.session_id")?;
        text(&self.attempt_id, "fingerprint.attempt_id")?;
        text(&self.route_fingerprint, "fingerprint.route_fingerprint")
    }
}

/// Expected cursor interval for one host-event stream.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamCursorRange {
    pub stream: String,
    pub first_expected_cursor: u64,
    pub last_expected_cursor: u64,
}

impl StreamCursorRange {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.stream, "cursor_range.stream")?;
        if self.last_expected_cursor < self.first_expected_cursor {
            return Err(EvaluationContractError::InvalidInterval {
                field: "cursor_range.first/last_expected_cursor",
            });
        }
        Ok(())
    }
}

/// Received/applied/rejected/unknown counts for one denominator.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCounts {
    pub received: u64,
    pub applied: u64,
    pub rejected: u64,
    pub unknown: u64,
}

impl EventCounts {
    /// Checked applied+rejected+unknown total. A saturating sum must not hide
    /// contradictory counts, so arithmetic overflow is a typed rejection.
    fn accounted(&self) -> Result<u64, EvaluationContractError> {
        self.applied
            .checked_add(self.rejected)
            .and_then(|sum| sum.checked_add(self.unknown))
            .ok_or(EvaluationContractError::EvidenceState {
                field: "counts.received/applied/rejected/unknown",
                reason: "applied, rejected and unknown counters overflow",
            })
    }

    fn validate(&self) -> Result<(), EvaluationContractError> {
        if self.accounted()? != self.received {
            return Err(EvaluationContractError::EvidenceState {
                field: "counts.received/applied/rejected/unknown",
                reason: "applied, rejected and unknown must fully account received events",
            });
        }
        Ok(())
    }
}

/// Ordering, replay and payload faults observed on the host-event path.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceFaults {
    pub gaps: u64,
    pub duplicates: u64,
    pub reorders: u64,
    pub payload_mutations: u64,
}

/// One cursor blind interval plus its missing-source reason.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageBlindInterval {
    pub stream: String,
    pub first_missing_cursor: u64,
    pub last_missing_cursor: u64,
    pub reason: String,
}

impl CoverageBlindInterval {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.stream, "blind_interval.stream")?;
        text(&self.reason, "blind_interval.reason")?;
        if self.last_missing_cursor < self.first_missing_cursor {
            return Err(EvaluationContractError::InvalidInterval {
                field: "blind_interval.first/last_missing_cursor",
            });
        }
        Ok(())
    }
}

/// Coverage for one material action or effect route.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialActionCoverage {
    pub action_or_effect_route: String,
    pub covered: bool,
    pub detail: String,
}

impl MaterialActionCoverage {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(
            &self.action_or_effect_route,
            "material_coverage.action_or_effect_route",
        )?;
        text(&self.detail, "material_coverage.detail")
    }
}

/// Denominator origin and sampling policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenominatorOrigin {
    pub origin: String,
    pub sampling_policy: String,
}

impl DenominatorOrigin {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.origin, "denominator_origin.origin")?;
        text(&self.sampling_policy, "denominator_origin.sampling_policy")
    }
}

fn unique_texts(values: &[String], field: &'static str) -> Result<(), EvaluationContractError> {
    let mut seen = BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(EvaluationContractError::DuplicateIdentity { field });
        }
    }
    Ok(())
}

/// Versioned denominator for one product/session/attempt/route fingerprint.
///
/// Every coverage claim binds this manifest: expected sources/classes, cursor
/// intervals, observable versus unobservable actions, count dispositions,
/// faults, blind intervals, per-material-action coverage, denominator origin,
/// completeness, proof ceiling, and invalidation dependencies.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationCoverageManifest {
    pub fingerprint: RunFingerprint,
    /// Allowed Tool/Facet manifest revision this denominator was built against.
    pub allowed_manifest_digest: String,
    pub expected_event_sources_and_event_classes: Vec<String>,
    pub observable_actions: Vec<String>,
    pub unobservable_actions: Vec<String>,
    pub first_and_last_expected_cursors_by_stream: Vec<StreamCursorRange>,
    pub counts: EventCounts,
    pub sequence_faults: SequenceFaults,
    pub blind_intervals_and_missing_source_reasons: Vec<CoverageBlindInterval>,
    pub missing_source_reasons: Vec<String>,
    pub coverage_by_material_action_and_effect_route: Vec<MaterialActionCoverage>,
    pub denominator_origin_and_sampling_policy: DenominatorOrigin,
    pub completeness: CoverageCompleteness,
    pub proof_ceiling: ProofCeiling,
    pub invalidation_dependencies: Vec<String>,
}

struct ProjectedChannelCoverage {
    expected: Vec<String>,
    streams: Vec<StreamCursorRange>,
    blind_intervals: Vec<CoverageBlindInterval>,
    missing_sources: Vec<String>,
    material: Vec<MaterialActionCoverage>,
}

fn project_channel_coverage(
    binding: &InstallationCoverageBinding,
    channels: &[InstallationChannelCoverage],
) -> ProjectedChannelCoverage {
    let mut projected = ProjectedChannelCoverage {
        expected: Vec::new(),
        streams: Vec::new(),
        blind_intervals: Vec::new(),
        missing_sources: Vec::new(),
        material: Vec::new(),
    };
    for channel in channels {
        let stream = format!("watchdog:{}", channel.channel);
        for class in &channel.expected_classes {
            projected
                .expected
                .push(format!("watchdog:{}:{class}", channel.channel));
        }
        projected.streams.push(StreamCursorRange {
            stream: stream.clone(),
            first_expected_cursor: binding.interval_start_ms,
            last_expected_cursor: binding.interval_end_ms,
        });
        // A replayed channel is covered by its evidence window, not live: no
        // blind interval, but the material detail names the replay so a
        // replayed stream never reads as live observation.
        let replayed = channel.disposition.as_str() == "JOURNAL_REPLAYED";
        let covered = channel.disposition.as_str() == "CONTINUOUS" || replayed;
        if !covered {
            projected.blind_intervals.push(CoverageBlindInterval {
                stream: stream.clone(),
                first_missing_cursor: binding.interval_start_ms,
                last_missing_cursor: binding.interval_end_ms,
                reason: format!("{}:{}", channel.channel, channel.gap_reasons.join(";")),
            });
            if channel.disposition.as_str() == "BLIND" {
                projected.missing_sources.push(format!(
                    "{}:{}",
                    channel.channel,
                    channel.gap_reasons.join(";")
                ));
            }
        }
        let replay_detail = channel
            .replay_evidence
            .as_ref()
            .map(|evidence| {
                format!(
                    "replay {}:{}..={}:{}",
                    evidence.journal_id,
                    evidence.first_cursor,
                    evidence.last_cursor,
                    channel.observed_replayed_observations
                )
            })
            .unwrap_or_default();
        projected.material.push(MaterialActionCoverage {
            action_or_effect_route: stream,
            covered,
            detail: format!(
                "source {}; expected [{}]; observed [{}]; disposition {}; dropped {}; replay {}; sensor_map {}; interval {}..={}",
                channel.expected_source,
                channel.expected_classes.join(","),
                channel.observed_classes.join(","),
                channel.disposition,
                channel.dropped_samples,
                replay_detail,
                binding.sensor_map_revision,
                binding.interval_start_ms,
                binding.interval_end_ms,
            ),
        });
    }
    projected
}

impl ObservationCoverageManifest {
    /// Validates the denominator shape. A `COMPLETE` denominator carries no
    /// blind intervals; anything else stays `PARTIAL`, `UNKNOWN`, or
    /// `NOT_APPLICABLE`. Sequence gaps and payload mutations must be localized
    /// to blind intervals so a derived trace can always name its blocker.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.fingerprint.validate()?;
        text(
            &self.allowed_manifest_digest,
            "manifest.allowed_manifest_digest",
        )?;
        if self.expected_event_sources_and_event_classes.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "manifest.expected_event_sources_and_event_classes",
            });
        }
        unique_texts(
            &self.expected_event_sources_and_event_classes,
            "manifest.expected_event_sources_and_event_classes",
        )?;
        unique_texts(&self.observable_actions, "manifest.observable_actions")?;
        unique_texts(&self.unobservable_actions, "manifest.unobservable_actions")?;
        for action in &self.observable_actions {
            if self.unobservable_actions.contains(action) {
                return Err(EvaluationContractError::DuplicateIdentity {
                    field: "manifest.observable/unobservable_actions",
                });
            }
        }
        if self.first_and_last_expected_cursors_by_stream.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "manifest.first_and_last_expected_cursors_by_stream",
            });
        }
        {
            let mut seen = BTreeSet::new();
            for range in &self.first_and_last_expected_cursors_by_stream {
                range.validate()?;
                if !seen.insert(range.stream.clone()) {
                    return Err(EvaluationContractError::DuplicateIdentity {
                        field: "manifest.first_and_last_expected_cursors_by_stream",
                    });
                }
            }
        }
        self.counts.validate()?;
        self.validate_blind_intervals_as_partition()?;
        unique_texts(
            &self.missing_source_reasons,
            "manifest.missing_source_reasons",
        )?;
        if self.coverage_by_material_action_and_effect_route.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "manifest.coverage_by_material_action_and_effect_route",
            });
        }
        {
            let mut seen = BTreeSet::new();
            for entry in &self.coverage_by_material_action_and_effect_route {
                entry.validate()?;
                if !seen.insert(entry.action_or_effect_route.clone()) {
                    return Err(EvaluationContractError::DuplicateIdentity {
                        field: "manifest.coverage_by_material_action_and_effect_route",
                    });
                }
            }
        }
        self.denominator_origin_and_sampling_policy.validate()?;
        self.validate_complete_denominator()?;
        if self.proof_ceiling > ProofCeiling::Observation {
            return Err(EvaluationContractError::ProofOverclaim);
        }
        if (self.sequence_faults.gaps > 0 || self.sequence_faults.payload_mutations > 0)
            && self.blind_intervals_and_missing_source_reasons.is_empty()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "manifest.blind_intervals_and_missing_source_reasons",
                reason: "sequence gaps or payload mutations require localized blind intervals",
            });
        }
        unique_texts(
            &self.invalidation_dependencies,
            "manifest.invalidation_dependencies",
        )
    }

    /// Validates blind intervals as one partition: every interval names a
    /// declared stream, lies inside its stream cursor range, and shares no
    /// cursor with another interval on the same stream.
    fn validate_blind_intervals_as_partition(&self) -> Result<(), EvaluationContractError> {
        for blind in &self.blind_intervals_and_missing_source_reasons {
            blind.validate()?;
            let range = self
                .first_and_last_expected_cursors_by_stream
                .iter()
                .find(|range| range.stream == blind.stream)
                .ok_or(EvaluationContractError::EvidenceState {
                    field: "manifest.blind_intervals_and_missing_source_reasons",
                    reason: "blind interval names a stream outside the declared cursor denominator",
                })?;
            if blind.first_missing_cursor < range.first_expected_cursor
                || blind.last_missing_cursor > range.last_expected_cursor
            {
                return Err(EvaluationContractError::EvidenceState {
                    field: "manifest.blind_intervals_and_missing_source_reasons",
                    reason: "blind interval lies outside its stream cursor range",
                });
            }
        }
        let mut ordered: Vec<(&str, u64, u64)> = self
            .blind_intervals_and_missing_source_reasons
            .iter()
            .map(|blind| {
                (
                    blind.stream.as_str(),
                    blind.first_missing_cursor,
                    blind.last_missing_cursor,
                )
            })
            .collect();
        ordered.sort_unstable();
        for pair in ordered.windows(2) {
            if pair[0].0 == pair[1].0 && pair[1].1 <= pair[0].2 {
                return Err(EvaluationContractError::EvidenceState {
                    field: "manifest.blind_intervals_and_missing_source_reasons",
                    reason: "blind intervals overlap and double-count one cursor",
                });
            }
        }
        Ok(())
    }

    /// Rejects a `Complete` denominator that carries blind intervals,
    /// missing-source reasons, uncovered material actions, unclassified
    /// events, or a received count the dispositions do not fully account.
    /// Non-complete denominators pass through untouched.
    fn validate_complete_denominator(&self) -> Result<(), EvaluationContractError> {
        if self.completeness != CoverageCompleteness::Complete {
            return Ok(());
        }
        if !self.blind_intervals_and_missing_source_reasons.is_empty() {
            return Err(EvaluationContractError::EvidenceState {
                field: "manifest.completeness",
                reason: "complete denominator cannot carry blind intervals",
            });
        }
        if !self.missing_source_reasons.is_empty() {
            return Err(EvaluationContractError::EvidenceState {
                field: "manifest.completeness",
                reason: "complete denominator cannot carry missing-source reasons",
            });
        }
        if self
            .coverage_by_material_action_and_effect_route
            .iter()
            .any(|entry| !entry.covered)
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "manifest.completeness",
                reason: "complete denominator cannot carry uncovered material actions",
            });
        }
        if self.counts.unknown > 0 {
            return Err(EvaluationContractError::EvidenceState {
                field: "manifest.completeness",
                reason: "complete denominator cannot carry received-but-unclassified events",
            });
        }
        if self.counts.accounted()? != self.counts.received {
            return Err(EvaluationContractError::EvidenceState {
                field: "manifest.completeness",
                reason: "complete denominator must fully account received events",
            });
        }
        Ok(())
    }

    /// Returns true only when `source_class` is a declared expected source or
    /// class of this denominator.
    #[must_use]
    pub fn declares_source_class(&self, source_class: &str) -> bool {
        self.expected_event_sources_and_event_classes
            .iter()
            .any(|entry| entry == source_class)
    }

    /// Joins one Watchdog interval-coverage report into this manifest owner
    /// without changing ownership (issue #1755 W6, I8.2).
    ///
    /// The Watchdog spool owns the per-channel interval report and the
    /// operational cursor/high-water state, which stay where they are: the
    /// export caller maps its record 1:1 into the owner-neutral
    /// [`InstallationChannelCoverage`] inputs and calls this constructor, so
    /// this crate gains no dependency edge on the Watchdog owner. Every
    /// carried field has an explicit image below; nothing is invented:
    ///
    /// ```text
    /// channel              -> stream `watchdog:<channel>`, material route
    ///                         `watchdog:<channel>`, and the qualifier of
    ///                         every expected-class, blind-reason and detail
    ///                         string, so no two channels share an image;
    /// expected source/classes -> `expected_event_sources_and_event_classes`
    ///                         as `watchdog:<channel>:<class>`, plus the
    ///                         material-route detail;
    /// observed live classes  -> the material-route detail (a live sample of
    ///                         an absent subject stays CONTINUOUS coverage of
    ///                         a bad health result; health itself is not
    ///                         carried here);
    /// dropped samples       -> `sequence_faults.gaps` and the channel's
    ///                         `SAMPLE_DROPPED` blind entry, never silence;
    /// unclosed interval     -> `UNKNOWN` with an `INTERVAL_NOT_CLOSED`
    ///                         blind entry on every wired channel;
    /// gap reasons           -> one `CoverageBlindInterval` per
    ///                         non-`CONTINUOUS` channel over that channel's
    ///                         own declared window, plus a
    ///                         `missing_source_reasons` entry per `BLIND`
    ///                         channel;
    /// sensor map revision   -> the attempt id, the sampling policy and the
    ///                         invalidation dependencies;
    /// installation identity -> the fingerprint product id and the
    ///                         invalidation dependencies.
    /// ```
    ///
    /// The fingerprint is installation-scoped by versioned convention, not by
    /// inventing a session: product id is the owner-issued installation
    /// identity, session id is [`INSTALLATION_COVERAGE_SESSION_ID`], the
    /// attempt id pins the binding version, sensor map revision and declared
    /// window, and the route fingerprint is [`INSTALLATION_COVERAGE_ROUTE`]
    /// at the binding version. Cursor ranges are the declared owner-clock
    /// window per channel stream: installation sensors have no journal
    /// cursor, so the window itself is the declared interval and a blind
    /// entry marks the channel window it names. Denominator completeness is
    /// derived, never chosen: all-`CONTINUOUS` yields `COMPLETE`, an
    /// all-`UNKNOWN` report yields `UNKNOWN`, anything else yields `PARTIAL`.
    /// A `COMPLETE` result therefore always validates gap-free, and any gap,
    /// drop, or unclassified channel blocks it through typed validation,
    /// not through caller discipline.
    ///
    /// Export acknowledgement semantics stay with the spool/export owner:
    /// this constructor only builds the denominator. A retained manifest is
    /// evidence, not resolution, and losing the daemon never discards the
    /// independently retained spool report this manifest was joined from.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationContractError`] when the binding or any channel
    /// input is malformed, when two channels share a name, when a record
    /// contradicts itself (replayed observations without a replay adapter,
    /// a non-continuous record naming no gap, a continuous record carrying
    /// gaps or drops, samples outside the expected classes, or an unclosed
    /// interval claiming a decided disposition), or when the joined
    /// denominator does not validate.
    pub fn for_installation_interval(
        binding: &InstallationCoverageBinding,
        channels: &[InstallationChannelCoverage],
    ) -> Result<Self, EvaluationContractError> {
        binding.validate()?;
        if channels.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "installation_coverage.channels",
            });
        }
        {
            let mut seen = BTreeSet::new();
            for channel in channels {
                channel.validate()?;
                if !seen.insert(channel.channel.as_str()) {
                    return Err(EvaluationContractError::DuplicateIdentity {
                        field: "installation_coverage.channels",
                    });
                }
            }
        }
        // A replayed channel is applied coverage by replay evidence, so it
        // counts with the live-continuous channels; `unknown` is whatever was
        // neither, never a conflation of replay with a gap.
        let mut applied = 0_u64;
        let mut unknown = 0_u64;
        let mut dropped_total = 0_u64;
        for channel in channels {
            match channel.disposition.as_str() {
                "CONTINUOUS" | "JOURNAL_REPLAYED" => applied += 1,
                "UNKNOWN" => unknown += 1,
                _ => {}
            }
            dropped_total = dropped_total
                .checked_add(u64::from(channel.dropped_samples))
                .ok_or(EvaluationContractError::EvidenceState {
                    field: "installation_coverage.dropped_samples",
                    reason: "dropped-sample counters overflow",
                })?;
        }
        let received = channels.len() as u64;
        let completeness = if applied == received {
            CoverageCompleteness::Complete
        } else if unknown == received {
            CoverageCompleteness::Unknown
        } else {
            CoverageCompleteness::Partial
        };
        let projected = project_channel_coverage(binding, channels);
        let manifest = Self {
            fingerprint: RunFingerprint {
                product_id: binding.installation_id.clone(),
                session_id: INSTALLATION_COVERAGE_SESSION_ID.to_owned(),
                attempt_id: format!(
                    "v{}-sensormap{}-{}..={}",
                    binding.binding_version,
                    binding.sensor_map_revision,
                    binding.interval_start_ms,
                    binding.interval_end_ms,
                ),
                route_fingerprint: format!(
                    "{}:v{}",
                    INSTALLATION_COVERAGE_ROUTE, binding.binding_version
                ),
            },
            allowed_manifest_digest: binding.allowed_manifest_digest.clone(),
            expected_event_sources_and_event_classes: projected.expected.clone(),
            observable_actions: projected.expected,
            unobservable_actions: Vec::new(),
            first_and_last_expected_cursors_by_stream: projected.streams,
            counts: EventCounts {
                received,
                applied,
                rejected: 0,
                unknown: received - applied,
            },
            sequence_faults: SequenceFaults {
                gaps: dropped_total,
                duplicates: 0,
                reorders: 0,
                payload_mutations: 0,
            },
            blind_intervals_and_missing_source_reasons: projected.blind_intervals,
            missing_source_reasons: projected.missing_sources,
            coverage_by_material_action_and_effect_route: projected.material,
            denominator_origin_and_sampling_policy: DenominatorOrigin {
                origin: INSTALLATION_COVERAGE_ORIGIN.to_owned(),
                sampling_policy: format!(
                    "one-tick-window sensor_map_revision {}",
                    binding.sensor_map_revision
                ),
            },
            completeness,
            proof_ceiling: ProofCeiling::Observation,
            invalidation_dependencies: vec![
                format!("installation:{}", binding.installation_id),
                format!("sensor-map:{}", binding.sensor_map_revision),
                format!(
                    "interval:{}..={}",
                    binding.interval_start_ms, binding.interval_end_ms
                ),
            ],
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

/// Version of the installation-level coverage binding declared below.
///
/// I8.2 Watchdog sensors observe an installation, not a product
/// session/attempt/route: there is no session to name. This version pins the
/// exact convention
/// [`ObservationCoverageManifest::for_installation_interval`] uses to bind
/// one installation window into a manifest fingerprint, so a future
/// convention change bumps this constant instead of silently reinterpreting
/// stored fields. Version 2 covers the five dispositions the Watchdog
/// interval publisher can produce (`CONTINUOUS`, `PARTIAL`, `BLIND`,
/// `UNKNOWN`, `JOURNAL_REPLAYED`); the replay disposition is only valid with
/// exact [`JournalReplayEvidence`], and no producer emits it until the W3
/// journal-replay adapter reports a replayed window.
pub const INSTALLATION_COVERAGE_BINDING_VERSION: u32 = 2;

/// Fixed session-scope literal for installation-level coverage.
///
/// The manifest fingerprint requires a nonempty session id, but an
/// installation sensor has no session. This literal marks the fingerprint as
/// installation-scoped instead of inventing a session; see
/// [`INSTALLATION_COVERAGE_BINDING_VERSION`].
pub const INSTALLATION_COVERAGE_SESSION_ID: &str = "installation";

/// Fixed route literal for Watchdog interval coverage (issue #1755, I8.2).
pub const INSTALLATION_COVERAGE_ROUTE: &str = "watchdog-interval-coverage";

/// Denominator origin carried by installation-interval manifests.
pub const INSTALLATION_COVERAGE_ORIGIN: &str = "watchdog-spool:interval-coverage";

/// Installation-level binding for one Watchdog interval-coverage window.
///
/// The Watchdog spool owns the interval report and the operational
/// cursor/high-water state; this struct only binds the identities the join
/// needs: the owner-issued installation identity, the caller-resolved allowed
/// Tool/Facet manifest digest the bound evidence must reference, the sensor
/// map revision the dispositions were derived under, and the declared
/// owner-clock window. `binding_version` must equal
/// [`INSTALLATION_COVERAGE_BINDING_VERSION`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationCoverageBinding {
    /// Owner-issued installation identity the sensors observed.
    pub installation_id: String,
    /// Caller-resolved allowed Tool/Facet manifest digest bound into the
    /// joined denominator.
    pub allowed_manifest_digest: String,
    /// Sensor map revision the interval dispositions were derived under.
    pub sensor_map_revision: u16,
    /// Owner-clock start of the declared interval, in milliseconds.
    pub interval_start_ms: u64,
    /// Owner-clock end of the declared interval, in milliseconds.
    pub interval_end_ms: u64,
    /// Binding convention version; must be
    /// [`INSTALLATION_COVERAGE_BINDING_VERSION`].
    pub binding_version: u32,
}

impl InstallationCoverageBinding {
    /// Validates the installation binding: both identities are non-blank,
    /// the version is current, and the window is ordered.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationContractError`] when an identity is blank, the
    /// version is not the current binding version, or the window end
    /// precedes its start.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(
            &self.installation_id,
            "installation_binding.installation_id",
        )?;
        text(
            &self.allowed_manifest_digest,
            "installation_binding.allowed_manifest_digest",
        )?;
        if self.binding_version != INSTALLATION_COVERAGE_BINDING_VERSION {
            return Err(EvaluationContractError::EvidenceState {
                field: "installation_binding.binding_version",
                reason: "installation coverage binding version is not the current version",
            });
        }
        if self.interval_end_ms < self.interval_start_ms {
            return Err(EvaluationContractError::InvalidInterval {
                field: "installation_binding.interval_start/end_ms",
            });
        }
        Ok(())
    }
}

/// Journal-replay evidence backing one `JOURNAL_REPLAYED` channel record.
///
/// The replay adapter (W3) covers a contiguous cursor window of one journal
/// and reports exactly the records it replayed. `first_cursor` and
/// `last_cursor` are the inclusive window bounds in that journal's cursor
/// space (USN for the filesystem journal); `observed_replayed_observations`
/// on the channel record must equal the window length, so a replay claim is
/// exact coverage of a named window rather than an approximate count.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalReplayEvidence {
    /// Journal identity the window was replayed from (journal name or id).
    pub journal_id: String,
    /// Inclusive first cursor of the replayed window.
    pub first_cursor: u64,
    /// Inclusive last cursor of the replayed window.
    pub last_cursor: u64,
}

impl JournalReplayEvidence {
    /// Validates replay evidence shape: the journal is named and the window
    /// is ordered.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationContractError`] when the journal identity is blank
    /// or the window end precedes its start.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.journal_id, "replay_evidence.journal_id")?;
        if self.last_cursor < self.first_cursor {
            return Err(EvaluationContractError::InvalidInterval {
                field: "replay_evidence.first/last_cursor",
            });
        }
        Ok(())
    }

    /// Returns the exact replayed-window length the channel record must carry.
    #[must_use]
    pub fn window_len(&self) -> u64 {
        self.last_cursor - self.first_cursor + 1
    }
}

/// One Watchdog channel's interval coverage in owner-neutral form.
///
/// This mirrors the spool owner's per-channel record field for field —
/// channel, competent source, expected classes, observed live classes,
/// replayed count with its replay evidence (binding version 2; always zero
/// and absent until the W3 replay adapter reports a replayed window),
/// dropped-sample count, whether the opening tick reached its close, the I8.2
/// wire disposition, and the named gap reasons — without importing the spool
/// owner, so the manifest owner gains no new dependency edge. The Watchdog
/// export caller maps its record 1:1 into this struct; see
/// [`ObservationCoverageManifest::for_installation_interval`] for the
/// lossless image of each field.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationChannelCoverage {
    /// I8.2 channel name as the spool owner reports it.
    pub channel: String,
    /// Competent source I8.2 expects to cover this channel.
    pub expected_source: String,
    /// Observation classes the expected source must support here.
    pub expected_classes: Vec<String>,
    /// Classes actually observed live in this interval.
    pub observed_classes: Vec<String>,
    /// Portions of the interval covered by journal replay; zero with no
    /// evidence until the replay adapter reports a replayed window.
    pub observed_replayed_observations: u32,
    /// Replay evidence for a `JOURNAL_REPLAYED` record; `None` otherwise.
    pub replay_evidence: Option<JournalReplayEvidence>,
    /// Live samples offered for this channel and then dropped.
    pub dropped_samples: u32,
    /// False for a window a tick opened and did not finish: only `UNKNOWN`
    /// may be claimed for it.
    pub interval_closed: bool,
    /// I8.2 wire disposition: `CONTINUOUS`, `PARTIAL`, `BLIND`, `UNKNOWN`,
    /// or `JOURNAL_REPLAYED` (binding version 2, only with replay evidence).
    pub disposition: String,
    /// Named omission reasons keeping this channel short of full coverage.
    pub gap_reasons: Vec<String>,
}

impl InstallationChannelCoverage {
    /// Validates one channel record: identities are non-blank, the
    /// disposition names a version-2 value, every observed class was
    /// expected exactly once, and the record is internally consistent (a
    /// replay claim only with exact replay evidence, no gapless
    /// non-continuous record, no gapped or dropped continuous record, no
    /// decided disposition over an unclosed window).
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationContractError`] when any of those checks fails.
    /// `JOURNAL_REPLAYED` is refused without exact evidence: the replayed
    /// count must equal the evidence window length, and evidence without the
    /// replay disposition is refused as an inconsistent record.
    /// Validates the disposition against the replay evidence it requires:
    /// `JOURNAL_REPLAYED` only with exact evidence whose window length the
    /// replayed count equals, every other disposition with neither evidence
    /// nor count. Kept beside [`validate`](Self::validate) so the record
    /// check stays within its line budget.
    fn validate_disposition_evidence(&self) -> Result<(), EvaluationContractError> {
        match self.disposition.as_str() {
            "CONTINUOUS" | "PARTIAL" | "BLIND" | "UNKNOWN" => {
                if self.replay_evidence.is_some() {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "installation_channel.replay_evidence",
                        reason: "replay evidence without the JOURNAL_REPLAYED disposition is an inconsistent record",
                    });
                }
                if self.observed_replayed_observations > 0 {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "installation_channel.observed_replayed_observations",
                        reason: "replayed observations need the JOURNAL_REPLAYED disposition with exact replay evidence",
                    });
                }
            }
            "JOURNAL_REPLAYED" => {
                let Some(evidence) = self.replay_evidence.as_ref() else {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "installation_channel.replay_evidence",
                        reason: "JOURNAL_REPLAYED needs exact journal-replay evidence",
                    });
                };
                evidence.validate()?;
                if u64::from(self.observed_replayed_observations) != evidence.window_len() {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "installation_channel.observed_replayed_observations",
                        reason: "replayed observations must equal the replay evidence window length",
                    });
                }
            }
            _ => {
                return Err(EvaluationContractError::EvidenceState {
                    field: "installation_channel.disposition",
                    reason: "unknown I8.2 disposition; version 2 binds CONTINUOUS, PARTIAL, BLIND, UNKNOWN and JOURNAL_REPLAYED only",
                });
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.channel, "installation_channel.channel")?;
        text(
            &self.expected_source,
            "installation_channel.expected_source",
        )?;
        text(&self.disposition, "installation_channel.disposition")?;
        self.validate_disposition_evidence()?;
        if self.expected_classes.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "installation_channel.expected_classes",
            });
        }
        unique_texts(
            &self.expected_classes,
            "installation_channel.expected_classes",
        )?;
        unique_texts(
            &self.observed_classes,
            "installation_channel.observed_classes",
        )?;
        for class in &self.observed_classes {
            text(class, "installation_channel.observed_classes")?;
            if !self.expected_classes.contains(class) {
                return Err(EvaluationContractError::EvidenceState {
                    field: "installation_channel.observed_classes",
                    reason: "observed class was not expected for this channel",
                });
            }
        }
        unique_texts(&self.gap_reasons, "installation_channel.gap_reasons")?;
        for reason in &self.gap_reasons {
            text(reason, "installation_channel.gap_reasons")?;
        }
        // A replayed channel carries the whole story in its evidence window:
        // no gaps (the replay closed them) and nothing dropped. A mixed
        // live-plus-replay interval with losses is PARTIAL, never replayed.
        let replayed = self.disposition.as_str() == "JOURNAL_REPLAYED";
        let continuous = self.disposition.as_str() == "CONTINUOUS";
        if continuous || replayed {
            if !self.gap_reasons.is_empty() {
                return Err(EvaluationContractError::EvidenceState {
                    field: "installation_channel.gap_reasons",
                    reason: "continuous channel cannot carry gap reasons",
                });
            }
            if self.dropped_samples > 0 {
                return Err(EvaluationContractError::EvidenceState {
                    field: "installation_channel.dropped_samples",
                    reason: "continuous channel cannot carry dropped samples",
                });
            }
            if continuous && self.observed_classes.is_empty() {
                return Err(EvaluationContractError::EvidenceState {
                    field: "installation_channel.observed_classes",
                    reason: "continuous channel needs an observed class",
                });
            }
        } else if self.gap_reasons.is_empty() {
            return Err(EvaluationContractError::EvidenceState {
                field: "installation_channel.gap_reasons",
                reason: "non-continuous channel must name its gap",
            });
        }
        if !self.interval_closed && self.disposition.as_str() != "UNKNOWN" {
            return Err(EvaluationContractError::EvidenceState {
                field: "installation_channel.interval_closed",
                reason: "unclosed interval cannot carry a decided disposition",
            });
        }
        Ok(())
    }
}

/// One immutable host/runtime record consumed by trace derivation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedToolCall {
    pub tool_name: String,
    pub declared: bool,
    pub forbidden: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedAccess {
    pub channel: String,
    pub target: String,
    pub declared: bool,
    pub hidden_schema_or_output_read: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedWrite {
    pub path: String,
    pub in_namespace: bool,
}

/// Immutable host/runtime evidence joined to one denominator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableHostEvidence {
    pub manifest_digest: String,
    pub observed_tool_calls: Vec<ObservedToolCall>,
    pub observed_non_tool_actions: Vec<String>,
    pub accesses: Vec<ObservedAccess>,
    pub writes: Vec<ObservedWrite>,
    pub external_effects: Vec<String>,
}

impl ImmutableHostEvidence {
    /// Validates immutable evidence shape without deriving any verdict.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.manifest_digest, "evidence.manifest_digest")?;
        for call in &self.observed_tool_calls {
            text(&call.tool_name, "evidence.tool_name")?;
        }
        unique_texts(
            &self.observed_non_tool_actions,
            "evidence.observed_non_tool_actions",
        )?;
        for access in &self.accesses {
            text(&access.channel, "evidence.access.channel")?;
            text(&access.target, "evidence.access.target")?;
        }
        for write in &self.writes {
            text(&write.path, "evidence.write.path")?;
        }
        unique_texts(&self.external_effects, "evidence.external_effects")
    }
}

/// Compliance trace derived only from immutable host/runtime records.
///
/// The trace always carries its explicit denominator (expected source count,
/// cursor ranges, count dispositions, and denominator completeness) plus its
/// disposition. A `PASS` names no blind interval and no undeclared access and
/// requires a complete denominator; `TAINTED` always names the blind interval
/// or undeclared access that blocks compliance; `UNKNOWN` carries the
/// incomplete denominator that blocks compliance plus any concrete blockers.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostObservedComplianceTrace {
    pub fingerprint: RunFingerprint,
    pub permitted_manifest_digest: String,
    pub observed_tool_calls: Vec<String>,
    pub observed_non_tool_actions: Vec<String>,
    pub accesses: Vec<String>,
    pub artifact_writes_and_external_effects: Vec<String>,
    pub expected_source_count: usize,
    pub expected_cursors_by_stream: Vec<StreamCursorRange>,
    pub received_applied_rejected_and_unknown_counts: EventCounts,
    pub blind_intervals: Vec<CoverageBlindInterval>,
    pub undeclared_accesses: Vec<String>,
    pub denominator_completeness: CoverageCompleteness,
    pub disposition: ComplianceDisposition,
    pub proof_ceiling: ProofCeiling,
}

impl HostObservedComplianceTrace {
    /// Validates denominator presence and disposition coherence: `PASS`
    /// carries no blind interval, no undeclared access, and a complete
    /// denominator, while `TAINTED` must name at least one blind interval or
    /// undeclared access and `UNKNOWN` must carry an incomplete denominator.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.fingerprint.validate()?;
        text(
            &self.permitted_manifest_digest,
            "trace.permitted_manifest_digest",
        )?;
        if self.expected_cursors_by_stream.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "trace.expected_cursors_by_stream",
            });
        }
        for range in &self.expected_cursors_by_stream {
            range.validate()?;
        }
        self.received_applied_rejected_and_unknown_counts
            .validate()?;
        for blind in &self.blind_intervals {
            blind.validate()?;
        }
        match self.disposition {
            ComplianceDisposition::Pass => {
                if !self.blind_intervals.is_empty() || !self.undeclared_accesses.is_empty() {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "trace.disposition",
                        reason: "compliant PASS cannot carry blind intervals or undeclared accesses",
                    });
                }
                if self.denominator_completeness != CoverageCompleteness::Complete {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "trace.denominator_completeness",
                        reason: "compliant PASS requires a complete denominator",
                    });
                }
            }
            ComplianceDisposition::Tainted => {
                if self.blind_intervals.is_empty() && self.undeclared_accesses.is_empty() {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "trace.disposition",
                        reason: "tainted trace must name a blind interval or undeclared access",
                    });
                }
            }
            ComplianceDisposition::Unknown => {
                if self.denominator_completeness == CoverageCompleteness::Complete {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "trace.denominator_completeness",
                        reason: "unknown trace requires an incomplete denominator",
                    });
                }
            }
            ComplianceDisposition::Fail => {}
        }
        if self.proof_ceiling > ProofCeiling::Observation {
            return Err(EvaluationContractError::ProofOverclaim);
        }
        Ok(())
    }
}

/// Manifest and evidence bound to one allowed Tool/Facet manifest revision.
///
/// The binding carries the independently resolved allowed-manifest digest
/// alongside the two objects and verifies, in one place, that both validate
/// and that both reference that exact revision for this run/attempt/route.
/// Validating two independent objects separately is not this join: only
/// [`derive_compliance_trace`] derives a disposition from a bound
/// input, and an unbound manifest plus evidence pair cannot produce a trace
/// through it.
pub struct BoundComplianceInputs<'a> {
    manifest: &'a ObservationCoverageManifest,
    evidence: &'a ImmutableHostEvidence,
    allowed_manifest_digest: &'a str,
}

impl<'a> BoundComplianceInputs<'a> {
    /// Validates the manifest and the evidence and verifies their common
    /// run/attempt/route/allowed-manifest binding: the manifest must carry
    /// the independently resolved allowed revision in its own
    /// `allowed_manifest_digest` field, and the evidence must reference that
    /// same revision. A caller-supplied digest matching neither side binds
    /// nothing and is rejected.
    pub fn bind(
        manifest: &'a ObservationCoverageManifest,
        evidence: &'a ImmutableHostEvidence,
        allowed_manifest_digest: &'a str,
    ) -> Result<Self, EvaluationContractError> {
        manifest.validate()?;
        evidence.validate()?;
        text(allowed_manifest_digest, "inputs.allowed_manifest_digest")?;
        if manifest.allowed_manifest_digest != allowed_manifest_digest {
            return Err(EvaluationContractError::EvidenceState {
                field: "manifest.allowed_manifest_digest",
                reason: "coverage manifest binds a different allowed manifest revision",
            });
        }
        if evidence.manifest_digest != manifest.allowed_manifest_digest {
            return Err(EvaluationContractError::EvidenceState {
                field: "evidence.manifest_digest",
                reason: "host evidence does not bind the manifest allowed revision",
            });
        }
        Ok(Self {
            manifest,
            evidence,
            allowed_manifest_digest,
        })
    }
}

/// Derives a [`HostObservedComplianceTrace`] from bound manifest and
/// evidence only. The binding is verified by
/// [`BoundComplianceInputs::bind`]; the derived trace carries the bound
/// allowed-manifest revision (refused typed when it does not, so the check
/// holds in release builds too, not only under `debug_assertions`) and is
/// re-validated before it is returned, so an invalid or unbound pair fails
/// typed instead of producing a valid `PASS`. This is the single derivation
/// scheme: no unbound manifest plus evidence pair can produce a trace.
///
/// Classification, in order: forbidden tool action yields `FAIL`;
/// undeclared or hidden access, out-of-namespace write, blind interval, or
/// cursor gap (sequence gaps and payload mutations) yields `TAINTED`;
/// received-but-unclassified events, uncovered material actions, or
/// missing-source reasons lower the denominator and yield `UNKNOWN`; a
/// non-complete denominator without a concrete taint signal yields `UNKNOWN`;
/// only a fully accounted complete denominator with no taint signal yields
/// `PASS`.
pub fn derive_compliance_trace(
    inputs: &BoundComplianceInputs<'_>,
) -> Result<HostObservedComplianceTrace, EvaluationContractError> {
    let trace = derive_core(inputs.manifest, inputs.evidence);
    if trace.permitted_manifest_digest != inputs.allowed_manifest_digest {
        return Err(EvaluationContractError::EvidenceState {
            field: "trace.permitted_manifest_digest",
            reason: "derived trace does not carry the bound allowed manifest revision",
        });
    }
    trace.validate()?;
    Ok(trace)
}

fn derive_core(
    manifest: &ObservationCoverageManifest,
    evidence: &ImmutableHostEvidence,
) -> HostObservedComplianceTrace {
    let mut undeclared: Vec<String> = Vec::new();
    let mut forbidden_seen = false;
    let mut observed_tools: Vec<String> = Vec::new();
    for call in &evidence.observed_tool_calls {
        observed_tools.push(call.tool_name.clone());
        if call.forbidden {
            forbidden_seen = true;
        }
        if !call.declared {
            undeclared.push(format!("undeclared-tool:{}", call.tool_name));
        }
    }
    let mut accesses: Vec<String> = Vec::new();
    for access in &evidence.accesses {
        accesses.push(format!("{}:{}", access.channel, access.target));
        if !access.declared {
            undeclared.push(format!(
                "undeclared-access:{}:{}",
                access.channel, access.target
            ));
        }
        if access.hidden_schema_or_output_read {
            undeclared.push(format!(
                "hidden-schema-or-output-read:{}:{}",
                access.channel, access.target
            ));
        }
    }
    let mut effects: Vec<String> = Vec::new();
    for write in &evidence.writes {
        effects.push(write.path.clone());
        if !write.in_namespace {
            undeclared.push(format!("out-of-namespace-write:{}", write.path));
        }
    }
    for effect in &evidence.external_effects {
        effects.push(effect.clone());
    }

    let cursor_gap =
        manifest.sequence_faults.gaps > 0 || manifest.sequence_faults.payload_mutations > 0;
    let has_blind = !manifest
        .blind_intervals_and_missing_source_reasons
        .is_empty();
    let denominator_gap = manifest.counts.unknown > 0
        || !manifest.missing_source_reasons.is_empty()
        || manifest
            .coverage_by_material_action_and_effect_route
            .iter()
            .any(|entry| !entry.covered);

    let disposition = if forbidden_seen {
        ComplianceDisposition::Fail
    } else if !undeclared.is_empty() || has_blind || cursor_gap {
        ComplianceDisposition::Tainted
    } else if manifest.completeness != CoverageCompleteness::Complete || denominator_gap {
        ComplianceDisposition::Unknown
    } else {
        ComplianceDisposition::Pass
    };
    let denominator_completeness = if disposition == ComplianceDisposition::Unknown
        && manifest.completeness == CoverageCompleteness::Complete
        && denominator_gap
    {
        CoverageCompleteness::Partial
    } else {
        manifest.completeness
    };

    let (blind_intervals, undeclared_accesses) = match disposition {
        ComplianceDisposition::Pass => (Vec::new(), Vec::new()),
        ComplianceDisposition::Fail => (
            manifest.blind_intervals_and_missing_source_reasons.clone(),
            undeclared,
        ),
        ComplianceDisposition::Tainted | ComplianceDisposition::Unknown => {
            let blind = manifest.blind_intervals_and_missing_source_reasons.clone();
            (blind, undeclared)
        }
    };

    HostObservedComplianceTrace {
        fingerprint: manifest.fingerprint.clone(),
        permitted_manifest_digest: evidence.manifest_digest.clone(),
        observed_tool_calls: observed_tools,
        observed_non_tool_actions: evidence.observed_non_tool_actions.clone(),
        accesses,
        artifact_writes_and_external_effects: effects,
        expected_source_count: manifest.expected_event_sources_and_event_classes.len(),
        expected_cursors_by_stream: manifest.first_and_last_expected_cursors_by_stream.clone(),
        received_applied_rejected_and_unknown_counts: manifest.counts,
        blind_intervals,
        undeclared_accesses,
        denominator_completeness,
        disposition,
        proof_ceiling: ProofCeiling::Observation,
    }
}

/// Returns true only when an absence-of-event claim for `source_class` is
/// admissible: the source/class is in the declared denominator, the
/// denominator is complete, no blind interval covers the claim, and no
/// sequence gap or payload mutation breaks cursor continuity.
#[must_use]
pub fn absence_claim_admissible(
    manifest: &ObservationCoverageManifest,
    source_class: &str,
) -> bool {
    complete_source_class_denominator_admissible(manifest, source_class)
}

fn complete_source_class_denominator_admissible(
    manifest: &ObservationCoverageManifest,
    source_class: &str,
) -> bool {
    manifest.validate().is_ok()
        && manifest.completeness == CoverageCompleteness::Complete
        && manifest.declares_source_class(source_class)
        && manifest
            .blind_intervals_and_missing_source_reasons
            .is_empty()
        && manifest.sequence_faults.gaps == 0
        && manifest.sequence_faults.payload_mutations == 0
}

/// Typed numerator proof linked to one exact declared source/class and cursor
/// interval. The denominator is never caller-chosen: it resolves from the
/// checked manifest stream range (`last - first + 1`), so `covered <= total`
/// alone cannot establish a percentage.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDenominatorProof {
    /// Declared source/class the numerator claims.
    pub source_class: String,
    /// Declared stream carrying the claimed interval.
    pub stream: String,
    /// First cursor of the claimed interval.
    pub first_cursor: u64,
    /// Last cursor of the claimed interval.
    pub last_cursor: u64,
    /// Covered events within the claimed interval.
    pub covered: u64,
}

impl CoverageDenominatorProof {
    /// Binds this proof to the checked denominator and resolves its exact
    /// total: the source/class must be admissible, the stream must declare
    /// exactly this cursor interval, and `covered` must not exceed the
    /// resolved span. Returns the resolved total.
    pub fn resolve_against(
        &self,
        manifest: &ObservationCoverageManifest,
    ) -> Result<u64, EvaluationContractError> {
        if !complete_source_class_denominator_admissible(manifest, &self.source_class) {
            return Err(EvaluationContractError::EvidenceState {
                field: "denominator_proof.source_class",
                reason: "source class is not in a declared complete gap-free denominator",
            });
        }
        let range = manifest
            .first_and_last_expected_cursors_by_stream
            .iter()
            .find(|range| range.stream == self.stream)
            .ok_or(EvaluationContractError::EvidenceState {
                field: "denominator_proof.stream",
                reason: "proof stream is outside the declared cursor denominator",
            })?;
        if range.first_expected_cursor != self.first_cursor
            || range.last_expected_cursor != self.last_cursor
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "denominator_proof.first/last_cursor",
                reason: "proof interval does not match the declared stream range",
            });
        }
        let total = self
            .last_cursor
            .checked_sub(self.first_cursor)
            .and_then(|span| span.checked_add(1))
            .ok_or(EvaluationContractError::InvalidInterval {
                field: "denominator_proof.first/last_cursor",
            })?;
        if self.covered > total {
            return Err(EvaluationContractError::EvidenceState {
                field: "denominator_proof.covered",
                reason: "covered events cannot exceed the resolved denominator",
            });
        }
        Ok(total)
    }
}

/// Returns a coverage percentage for a typed denominator proof bound to one
/// exact source/class and cursor interval; otherwise returns `None`.
#[allow(clippy::cast_precision_loss)]
#[must_use]
pub fn coverage_percentage_for_proof(
    manifest: &ObservationCoverageManifest,
    proof: &CoverageDenominatorProof,
) -> Option<f64> {
    match proof.resolve_against(manifest) {
        Ok(total) if total > 0 => Some((proof.covered as f64 / total as f64) * 100.0),
        _ => None,
    }
}

/// Returns a coverage percentage only for `source_class` in a valid, declared
/// complete single-stream denominator with continuous cursors, a consistent
/// numerator, and a caller total that equals the checked manifest received
/// count; otherwise returns `None`. A numerator above the denominator is
/// inconsistent evidence, never a valid claim above 100 %, and an arbitrary
/// denominator is refused even when `covered <= total` holds. A multi-stream
/// denominator refuses here because the global received count cannot bind a
/// per-source claim to its exact stream interval; that claim requires the
/// typed [`CoverageDenominatorProof`] via [`coverage_percentage_for_proof`].
#[allow(clippy::cast_precision_loss)]
#[must_use]
pub fn coverage_percentage(
    manifest: &ObservationCoverageManifest,
    source_class: &str,
    covered: u64,
    total: u64,
) -> Option<f64> {
    if !complete_source_class_denominator_admissible(manifest, source_class) || total == 0 {
        return None;
    }
    if manifest.first_and_last_expected_cursors_by_stream.len() != 1 {
        return None;
    }
    if total != manifest.counts.received {
        return None;
    }
    if covered > total {
        return None;
    }
    Some((covered as f64 / total as f64) * 100.0)
}

/// Resolves the exact source-dependency handles one retained trace version
/// depends on: the allowed Tool/Facet manifest revision the denominator was
/// built against, the manifest-declared invalidation handles, and one handle
/// per declared stream cursor interval. Handles derive only from an already
/// validated manifest (see [`BoundComplianceInputs::bind`]); repeats collapse
/// so retention never fails typed on a duplicated handle.
fn retention_source_dependencies(manifest: &ObservationCoverageManifest) -> Vec<String> {
    let mut dependencies = Vec::new();
    let mut push_unique = |handle: String| {
        if !dependencies.contains(&handle) {
            dependencies.push(handle);
        }
    };
    push_unique(format!(
        "allowed-manifest:{}",
        manifest.allowed_manifest_digest
    ));
    for dependency in &manifest.invalidation_dependencies {
        push_unique(dependency.clone());
    }
    for range in &manifest.first_and_last_expected_cursors_by_stream {
        push_unique(format!(
            "stream-cursor:{}:{}..={}",
            range.stream, range.first_expected_cursor, range.last_expected_cursor
        ));
    }
    dependencies
}

/// One retained compliance trace version with its source dependencies.
///
/// The record carries the exact invalidation handles the trace depends on
/// (manifest `invalidation_dependencies`, the allowed-manifest digest, and
/// the journal stream cursors bound at derivation). `superseded` marks an
/// older version replaced by a newer trace for the same fingerprint;
/// `applicable` is lowered only by source invalidation, reparse, or
/// revocation through [`ComplianceTraceLedger::invalidate_source`]. The
/// ledger is pure and opens no database: retention is an in-memory
/// append-only record owned by the evaluation-evidence writer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedComplianceTrace {
    /// Ledger-assigned version, contiguous from one.
    pub trace_version: u64,
    /// Retained trace at this version.
    pub trace: HostObservedComplianceTrace,
    /// Exact invalidation handles this version depends on.
    pub source_dependencies: Vec<String>,
    /// True once a newer version of the same fingerprint is appended.
    pub superseded: bool,
    /// False once a depended source is invalidated, reparsed, or revoked.
    pub applicable: bool,
}

impl VersionedComplianceTrace {
    /// Validates version presence, trace coherence, and dependency handles.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        if self.trace_version == 0 {
            return Err(EvaluationContractError::InvalidInterval {
                field: "versioned_trace.trace_version",
            });
        }
        self.trace.validate()?;
        unique_texts(
            &self.source_dependencies,
            "versioned_trace.source_dependencies",
        )
    }
}

/// Append-only retention for compliance traces with revalidation rules.
///
/// Appending a trace for a fingerprint supersedes older versions of that
/// same fingerprint without deleting them; source invalidation lowers
/// `applicable` on every dependent version. [`Self::current_for`] serves the
/// latest applicable version for the requested fingerprint only: a
/// historical `PASS` on another fingerprint never becomes current, and an
/// invalidated trace never silently recovers.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceTraceLedger {
    /// Ledger identity.
    pub ledger_id: String,
    /// Retained versions in append order.
    pub records: Vec<VersionedComplianceTrace>,
}

impl ComplianceTraceLedger {
    /// Creates an empty ledger under `ledger_id`.
    #[must_use]
    pub fn new(ledger_id: String) -> Self {
        Self {
            ledger_id,
            records: Vec::new(),
        }
    }

    /// Validates the ledger identity, every retained version, and version
    /// contiguity.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.ledger_id, "trace_ledger.ledger_id")?;
        for (index, record) in self.records.iter().enumerate() {
            record.validate()?;
            let expected =
                (index as u64)
                    .checked_add(1)
                    .ok_or(EvaluationContractError::InvalidInterval {
                        field: "trace_ledger.records.trace_version",
                    })?;
            if record.trace_version != expected {
                return Err(EvaluationContractError::EvidenceState {
                    field: "trace_ledger.records.trace_version",
                    reason: "trace versions must be contiguous from one",
                });
            }
        }
        Ok(())
    }

    /// Retains one validated trace with its source dependencies, supersedes
    /// older versions of the same fingerprint, and returns the assigned
    /// version. An invalid trace is refused typed and retained nowhere, as is
    /// a version carrying no source dependency: without at least one
    /// invalidation handle no source change could ever lower the version, so
    /// dependency-free retention is rejected fail-closed.
    pub fn append(
        &mut self,
        trace: HostObservedComplianceTrace,
        source_dependencies: Vec<String>,
    ) -> Result<u64, EvaluationContractError> {
        trace.validate()?;
        if source_dependencies.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "versioned_trace.source_dependencies",
            });
        }
        unique_texts(&source_dependencies, "versioned_trace.source_dependencies")?;
        let version = (self.records.len() as u64).checked_add(1).ok_or(
            EvaluationContractError::InvalidInterval {
                field: "trace_ledger.records.trace_version",
            },
        )?;
        for record in &mut self.records {
            if record.trace.fingerprint == trace.fingerprint {
                record.superseded = true;
            }
        }
        self.records.push(VersionedComplianceTrace {
            trace_version: version,
            trace,
            source_dependencies,
            superseded: false,
            applicable: true,
        });
        Ok(version)
    }

    /// Lowers `applicable` on every retained version depending on `source`
    /// (invalidation, reparse, or revocation of that source). Returns the
    /// number of versions lowered. Lowered versions never silently recover:
    /// only a new append for the fingerprint becomes current.
    pub fn invalidate_source(&mut self, source: &str) -> usize {
        let mut lowered = 0;
        for record in &mut self.records {
            if record.applicable && record.source_dependencies.iter().any(|dep| dep == source) {
                record.applicable = false;
                lowered += 1;
            }
        }
        lowered
    }

    /// Retains the trace derived from one bound manifest plus evidence pair
    /// with source dependencies resolved from the manifest itself (issue
    /// #1936 W1, I7.23).
    ///
    /// This is the single retention scheme for bound derivations: the trace
    /// comes only from [`derive_compliance_trace`], so an invalid or unbound
    /// pair fails typed and is retained nowhere, and the dependencies always
    /// bind the allowed-manifest revision, the manifest-declared invalidation
    /// handles, and the exact stream cursor intervals the denominator was
    /// built against. A retained version therefore always carries the handles
    /// [`Self::invalidate_source`] needs: source invalidation, reparse, or
    /// revocation lowers `applicable`, older versions of the same fingerprint
    /// are superseded without deletion, and [`Self::current_for`] never
    /// promotes a historical `PASS` onto a new fingerprint. The ledger stays
    /// pure in-memory retention owned by the evaluation-evidence writer: it
    /// opens no database.
    pub fn retain_derived(
        &mut self,
        inputs: &BoundComplianceInputs<'_>,
    ) -> Result<u64, EvaluationContractError> {
        let trace = derive_compliance_trace(inputs)?;
        let source_dependencies = retention_source_dependencies(inputs.manifest);
        self.append(trace, source_dependencies)
    }

    /// Returns the latest applicable version for `fingerprint`, or `None`
    /// when no applicable version exists for it.
    #[must_use]
    pub fn current_for(&self, fingerprint: &RunFingerprint) -> Option<&VersionedComplianceTrace> {
        self.records
            .iter()
            .rev()
            .find(|record| record.applicable && record.trace.fingerprint == *fingerprint)
    }
}

#[cfg(test)]
mod coverage_trace_tests_1936 {
    use super::*;

    fn fingerprint() -> RunFingerprint {
        RunFingerprint {
            product_id: "product-1936".to_owned(),
            session_id: "session-1936".to_owned(),
            attempt_id: "attempt-1936".to_owned(),
            route_fingerprint: "route-1936".to_owned(),
        }
    }

    fn complete_manifest() -> ObservationCoverageManifest {
        ObservationCoverageManifest {
            fingerprint: fingerprint(),
            allowed_manifest_digest: "manifest-digest-1936".to_owned(),
            expected_event_sources_and_event_classes: vec![
                "host.shell".to_owned(),
                "host.filesystem".to_owned(),
            ],
            observable_actions: vec!["shell.exec".to_owned()],
            unobservable_actions: vec!["provider.hidden-reasoning".to_owned()],
            first_and_last_expected_cursors_by_stream: vec![StreamCursorRange {
                stream: "host-events".to_owned(),
                first_expected_cursor: 1,
                last_expected_cursor: 4,
            }],
            counts: EventCounts {
                received: 4,
                applied: 4,
                rejected: 0,
                unknown: 0,
            },
            sequence_faults: SequenceFaults {
                gaps: 0,
                duplicates: 0,
                reorders: 0,
                payload_mutations: 0,
            },
            blind_intervals_and_missing_source_reasons: Vec::new(),
            missing_source_reasons: Vec::new(),
            coverage_by_material_action_and_effect_route: vec![MaterialActionCoverage {
                action_or_effect_route: "shell.exec:declared".to_owned(),
                covered: true,
                detail: "observed on cursor 1..=4".to_owned(),
            }],
            denominator_origin_and_sampling_policy: DenominatorOrigin {
                origin: "host-state-journal".to_owned(),
                sampling_policy: "full".to_owned(),
            },
            completeness: CoverageCompleteness::Complete,
            proof_ceiling: ProofCeiling::Observation,
            invalidation_dependencies: vec!["journal-wrap".to_owned()],
        }
    }

    fn clean_evidence() -> ImmutableHostEvidence {
        ImmutableHostEvidence {
            manifest_digest: "manifest-digest-1936".to_owned(),
            observed_tool_calls: vec![ObservedToolCall {
                tool_name: "shell.exec".to_owned(),
                declared: true,
                forbidden: false,
            }],
            observed_non_tool_actions: vec!["prompt.submit".to_owned()],
            accesses: vec![ObservedAccess {
                channel: "shell".to_owned(),
                target: "declared-command".to_owned(),
                declared: true,
                hidden_schema_or_output_read: false,
            }],
            writes: vec![ObservedWrite {
                path: "namespace/artifact.json".to_owned(),
                in_namespace: true,
            }],
            external_effects: Vec::new(),
        }
    }

    #[test]
    fn complete_source_clean_run_yields_pass_with_explicit_denominator() {
        let manifest = complete_manifest();
        assert!(manifest.validate().is_ok());
        let evidence = clean_evidence();
        let inputs = BoundComplianceInputs::bind(&manifest, &evidence, "manifest-digest-1936")
            .expect("bound test inputs");
        let trace = derive_compliance_trace(&inputs).expect("derived test trace");
        assert!(trace.validate().is_ok());
        assert_eq!(trace.disposition, ComplianceDisposition::Pass);
        assert_eq!(trace.expected_source_count, 2);
        assert!(!trace.expected_cursors_by_stream.is_empty());
        assert_eq!(
            trace.received_applied_rejected_and_unknown_counts.received,
            4
        );
        assert!(absence_claim_admissible(&manifest, "host.shell"));
        assert!(coverage_percentage(&manifest, "host.shell", 4, 4).is_some());
    }

    #[test]
    fn cursor_gap_yields_tainted_naming_blind_interval_never_pass() {
        let mut manifest = complete_manifest();
        manifest.completeness = CoverageCompleteness::Partial;
        manifest.sequence_faults.gaps = 1;
        manifest
            .blind_intervals_and_missing_source_reasons
            .push(CoverageBlindInterval {
                stream: "host-events".to_owned(),
                first_missing_cursor: 3,
                last_missing_cursor: 3,
                reason: "journal-gap".to_owned(),
            });
        assert!(manifest.validate().is_ok());
        let evidence = clean_evidence();
        let inputs = BoundComplianceInputs::bind(&manifest, &evidence, "manifest-digest-1936")
            .expect("bound test inputs");
        let trace = derive_compliance_trace(&inputs).expect("derived test trace");
        assert!(trace.validate().is_ok());
        assert_ne!(trace.disposition, ComplianceDisposition::Pass);
        assert_eq!(trace.disposition, ComplianceDisposition::Tainted);
        assert!(
            trace
                .blind_intervals
                .iter()
                .any(|blind| blind.first_missing_cursor == 3)
        );
        assert!(!absence_claim_admissible(&manifest, "host.shell"));
        assert!(coverage_percentage(&manifest, "host.shell", 3, 4).is_none());
    }

    #[test]
    fn undeclared_shell_read_yields_tainted_naming_access_never_pass() {
        let manifest = complete_manifest();
        let mut evidence = clean_evidence();
        evidence.accesses.push(ObservedAccess {
            channel: "shell".to_owned(),
            target: "hidden-output-file".to_owned(),
            declared: false,
            hidden_schema_or_output_read: true,
        });
        assert!(evidence.validate().is_ok());
        let inputs = BoundComplianceInputs::bind(&manifest, &evidence, "manifest-digest-1936")
            .expect("bound test inputs");
        let trace = derive_compliance_trace(&inputs).expect("derived test trace");
        assert!(trace.validate().is_ok());
        assert_ne!(trace.disposition, ComplianceDisposition::Pass);
        assert_eq!(trace.disposition, ComplianceDisposition::Tainted);
        assert!(
            trace
                .undeclared_accesses
                .iter()
                .any(|entry| entry.contains("hidden-output-file"))
        );
    }

    #[test]
    fn payload_mutation_blocks_absence_and_percentage_naming_blind_interval() {
        let mut manifest = complete_manifest();
        manifest.completeness = CoverageCompleteness::Partial;
        manifest.sequence_faults.payload_mutations = 1;
        manifest
            .blind_intervals_and_missing_source_reasons
            .push(CoverageBlindInterval {
                stream: "host-events".to_owned(),
                first_missing_cursor: 2,
                last_missing_cursor: 2,
                reason: "payload-mismatch".to_owned(),
            });
        assert!(manifest.validate().is_ok());
        let evidence = clean_evidence();
        let inputs = BoundComplianceInputs::bind(&manifest, &evidence, "manifest-digest-1936")
            .expect("bound test inputs");
        let trace = derive_compliance_trace(&inputs).expect("derived test trace");
        assert!(trace.validate().is_ok());
        assert_eq!(trace.disposition, ComplianceDisposition::Tainted);
        assert!(
            trace
                .blind_intervals
                .iter()
                .any(|blind| blind.reason == "payload-mismatch")
        );
        assert!(!absence_claim_admissible(&manifest, "host.shell"));
        assert!(coverage_percentage(&manifest, "host.shell", 3, 4).is_none());
    }

    #[test]
    fn payload_mutation_alone_blocks_absence_and_percentage() {
        let mut manifest = complete_manifest();
        manifest.sequence_faults.payload_mutations = 1;
        assert!(!absence_claim_admissible(&manifest, "host.shell"));
        assert!(coverage_percentage(&manifest, "host.shell", 4, 4).is_none());
    }

    #[test]
    fn cursor_gap_without_percentage_denominator_is_rejected() {
        let manifest = complete_manifest();
        assert!(coverage_percentage(&manifest, "host.shell", 4, 4).is_some());
        let mut gapped = complete_manifest();
        gapped.sequence_faults.gaps = 1;
        assert!(coverage_percentage(&gapped, "host.shell", 4, 4).is_none());
    }

    #[test]
    fn inconsistent_numerator_is_refused_never_over_one_hundred() {
        let manifest = complete_manifest();
        assert_eq!(
            coverage_percentage(&manifest, "host.shell", 4, 4),
            Some(100.0)
        );
        assert!(coverage_percentage(&manifest, "host.shell", 5, 4).is_none());
        assert!(coverage_percentage(&manifest, "host.shell", 1, 0).is_none());
    }

    #[test]
    fn unlocalized_sequence_fault_is_rejected_fail_closed() {
        let mut manifest = complete_manifest();
        manifest.sequence_faults.gaps = 1;
        assert!(manifest.validate().is_err());
        let mut partial = complete_manifest();
        partial.completeness = CoverageCompleteness::Partial;
        partial.sequence_faults.payload_mutations = 1;
        assert!(partial.validate().is_err());
    }

    #[test]
    fn partial_denominator_clean_run_yields_unknown_with_explicit_completeness() {
        let mut manifest = complete_manifest();
        manifest.completeness = CoverageCompleteness::Partial;
        assert!(manifest.validate().is_ok());
        let evidence = clean_evidence();
        let inputs = BoundComplianceInputs::bind(&manifest, &evidence, "manifest-digest-1936")
            .expect("bound test inputs");
        let trace = derive_compliance_trace(&inputs).expect("derived test trace");
        assert_eq!(trace.disposition, ComplianceDisposition::Unknown);
        assert!(trace.validate().is_ok());
        assert_eq!(
            trace.denominator_completeness,
            CoverageCompleteness::Partial
        );
        assert!(!absence_claim_admissible(&manifest, "host.shell"));
        assert!(coverage_percentage(&manifest, "host.shell", 3, 4).is_none());
    }

    #[test]
    fn pass_requires_complete_denominator() {
        let manifest = complete_manifest();
        let evidence = clean_evidence();
        let inputs = BoundComplianceInputs::bind(&manifest, &evidence, "manifest-digest-1936")
            .expect("bound test inputs");
        let mut trace = derive_compliance_trace(&inputs).expect("derived test trace");
        assert_eq!(trace.disposition, ComplianceDisposition::Pass);
        assert!(trace.validate().is_ok());
        trace.denominator_completeness = CoverageCompleteness::Partial;
        assert!(trace.validate().is_err());
    }
}

#[cfg(test)]
mod coverage_replay_evidence_tests_1755 {
    use super::*;

    fn exact_evidence() -> JournalReplayEvidence {
        JournalReplayEvidence {
            journal_id: "filesystem-usn-journal".to_owned(),
            first_cursor: 100,
            last_cursor: 109,
        }
    }

    fn replayed_channel(
        count: u32,
        evidence: Option<JournalReplayEvidence>,
    ) -> InstallationChannelCoverage {
        InstallationChannelCoverage {
            channel: "filesystem-journal".to_owned(),
            expected_source: "filesystem change journal".to_owned(),
            expected_classes: vec!["path-change".to_owned()],
            observed_classes: Vec::new(),
            observed_replayed_observations: count,
            replay_evidence: evidence,
            dropped_samples: 0,
            interval_closed: true,
            disposition: "JOURNAL_REPLAYED".to_owned(),
            gap_reasons: Vec::new(),
        }
    }

    /// Binding version 2 (#1755 A2): a `JOURNAL_REPLAYED` record with exact
    /// evidence whose window length equals the replayed count validates.
    #[test]
    fn journal_replayed_with_exact_evidence_validates() {
        assert!(
            replayed_channel(10, Some(exact_evidence()))
                .validate()
                .is_ok()
        );
    }

    /// The replay disposition without evidence is a bare claim, refused.
    #[test]
    fn journal_replayed_without_evidence_is_refused() {
        assert!(replayed_channel(10, None).validate().is_err());
    }

    /// The replayed count must equal the evidence window length exactly:
    /// an approximate count is not coverage of a named window.
    #[test]
    fn replayed_count_must_equal_evidence_window_length() {
        assert!(
            replayed_channel(9, Some(exact_evidence()))
                .validate()
                .is_err()
        );
        assert!(
            replayed_channel(11, Some(exact_evidence()))
                .validate()
                .is_err()
        );
    }

    /// Evidence without the replay disposition is an inconsistent record,
    /// refused on every other disposition.
    #[test]
    fn replay_evidence_without_replay_disposition_is_refused() {
        let mut channel = replayed_channel(0, Some(exact_evidence()));
        channel.disposition = "CONTINUOUS".to_owned();
        channel.observed_classes = vec!["path-change".to_owned()];
        assert!(channel.validate().is_err());
    }

    /// A bare replayed count without the disposition and evidence proves
    /// only parsing shape, never coverage (a malformed-text negative is not
    /// a real refusal leg).
    #[test]
    fn replayed_count_without_disposition_is_refused() {
        let mut channel = replayed_channel(10, None);
        channel.disposition = "UNKNOWN".to_owned();
        channel.gap_reasons = vec!["NO_COMPETENT_SOURCE".to_owned()];
        assert!(channel.validate().is_err());
    }

    /// Malformed evidence shape (blank journal, inverted window) is refused
    /// at the evidence layer, before any count comparison.
    #[test]
    fn malformed_evidence_shape_is_refused() {
        let mut blank = exact_evidence();
        blank.journal_id = String::new();
        assert!(blank.validate().is_err());
        let mut inverted = exact_evidence();
        inverted.first_cursor = 200;
        inverted.last_cursor = 100;
        assert!(inverted.validate().is_err());
        assert!(exact_evidence().validate().is_ok());
        assert_eq!(exact_evidence().window_len(), 10);
    }
}
