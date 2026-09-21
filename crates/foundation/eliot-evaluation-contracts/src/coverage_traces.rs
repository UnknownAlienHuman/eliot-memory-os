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
    fn validate(&self) -> Result<(), EvaluationContractError> {
        if self
            .applied
            .saturating_add(self.rejected)
            .saturating_add(self.unknown)
            > self.received
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "counts.received/applied/rejected/unknown",
                reason: "applied, rejected and unknown cannot exceed received",
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

impl ObservationCoverageManifest {
    /// Validates the denominator shape. A `COMPLETE` denominator carries no
    /// blind intervals; anything else stays `PARTIAL`, `UNKNOWN`, or
    /// `NOT_APPLICABLE`. Sequence gaps and payload mutations must be localized
    /// to blind intervals so a derived trace can always name its blocker.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.fingerprint.validate()?;
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
        for blind in &self.blind_intervals_and_missing_source_reasons {
            blind.validate()?;
        }
        unique_texts(
            &self.missing_source_reasons,
            "manifest.missing_source_reasons",
        )?;
        if self.coverage_by_material_action_and_effect_route.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "manifest.coverage_by_material_action_and_effect_route",
            });
        }
        for entry in &self.coverage_by_material_action_and_effect_route {
            entry.validate()?;
        }
        self.denominator_origin_and_sampling_policy.validate()?;
        if self.completeness == CoverageCompleteness::Complete
            && !self.blind_intervals_and_missing_source_reasons.is_empty()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "manifest.completeness",
                reason: "complete denominator cannot carry blind intervals",
            });
        }
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

    /// Returns true only when `source_class` is a declared expected source or
    /// class of this denominator.
    #[must_use]
    pub fn declares_source_class(&self, source_class: &str) -> bool {
        self.expected_event_sources_and_event_classes
            .iter()
            .any(|entry| entry == source_class)
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

/// Derives a [`HostObservedComplianceTrace`] only from immutable host/runtime
/// records joined to the permitted denominator.
///
/// Classification, in order: forbidden tool action yields `FAIL`;
/// undeclared or hidden access, out-of-namespace write, blind interval, or
/// cursor gap (sequence gaps and payload mutations) yields `TAINTED`; a
/// non-complete denominator without a concrete taint signal yields `UNKNOWN`;
/// only a complete denominator with no taint signal yields `PASS`. The result
/// always carries the explicit denominator including its completeness and can
/// never present a gapped or undeclared run as compliant `PASS`. Callers join
/// a validated manifest: sequence faults without localized blind intervals are
/// rejected by [`ObservationCoverageManifest::validate`], so a trace derived
/// from a valid manifest always satisfies [`HostObservedComplianceTrace::validate`].
#[must_use]
pub fn derive_compliance_trace(
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

    let disposition = if forbidden_seen {
        ComplianceDisposition::Fail
    } else if !undeclared.is_empty() || has_blind || cursor_gap {
        ComplianceDisposition::Tainted
    } else if manifest.completeness != CoverageCompleteness::Complete {
        ComplianceDisposition::Unknown
    } else {
        ComplianceDisposition::Pass
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
        denominator_completeness: manifest.completeness,
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
    manifest.completeness == CoverageCompleteness::Complete
        && manifest.declares_source_class(source_class)
        && manifest
            .blind_intervals_and_missing_source_reasons
            .is_empty()
        && manifest.sequence_faults.gaps == 0
        && manifest.sequence_faults.payload_mutations == 0
}

/// Returns a coverage percentage only against a declared complete
/// denominator with continuous cursors; otherwise returns `None` so
/// percentages without an explicit gap-free denominator are rejected rather
/// than rendered.
#[allow(clippy::cast_precision_loss)]
#[must_use]
pub fn coverage_percentage(
    manifest: &ObservationCoverageManifest,
    covered: u64,
    total: u64,
) -> Option<f64> {
    if manifest.completeness != CoverageCompleteness::Complete || total == 0 {
        return None;
    }
    if !manifest
        .blind_intervals_and_missing_source_reasons
        .is_empty()
    {
        return None;
    }
    if manifest.sequence_faults.gaps > 0 || manifest.sequence_faults.payload_mutations > 0 {
        return None;
    }
    Some((covered as f64 / total as f64) * 100.0)
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
        let trace = derive_compliance_trace(&manifest, &clean_evidence());
        assert!(trace.validate().is_ok());
        assert_eq!(trace.disposition, ComplianceDisposition::Pass);
        assert_eq!(trace.expected_source_count, 2);
        assert!(!trace.expected_cursors_by_stream.is_empty());
        assert_eq!(
            trace.received_applied_rejected_and_unknown_counts.received,
            4
        );
        assert!(absence_claim_admissible(&manifest, "host.shell"));
        assert!(coverage_percentage(&manifest, 4, 4).is_some());
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
        let trace = derive_compliance_trace(&manifest, &clean_evidence());
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
        assert!(coverage_percentage(&manifest, 3, 4).is_none());
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
        let trace = derive_compliance_trace(&manifest, &evidence);
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
        let trace = derive_compliance_trace(&manifest, &clean_evidence());
        assert!(trace.validate().is_ok());
        assert_eq!(trace.disposition, ComplianceDisposition::Tainted);
        assert!(
            trace
                .blind_intervals
                .iter()
                .any(|blind| blind.reason == "payload-mismatch")
        );
        assert!(!absence_claim_admissible(&manifest, "host.shell"));
        assert!(coverage_percentage(&manifest, 3, 4).is_none());
    }

    #[test]
    fn payload_mutation_alone_blocks_absence_and_percentage() {
        let mut manifest = complete_manifest();
        manifest.sequence_faults.payload_mutations = 1;
        assert!(!absence_claim_admissible(&manifest, "host.shell"));
        assert!(coverage_percentage(&manifest, 4, 4).is_none());
    }

    #[test]
    fn cursor_gap_without_percentage_denominator_is_rejected() {
        let manifest = complete_manifest();
        assert!(coverage_percentage(&manifest, 4, 4).is_some());
        let mut gapped = complete_manifest();
        gapped.sequence_faults.gaps = 1;
        assert!(coverage_percentage(&gapped, 4, 4).is_none());
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
        let trace = derive_compliance_trace(&manifest, &clean_evidence());
        assert_eq!(trace.disposition, ComplianceDisposition::Unknown);
        assert!(trace.validate().is_ok());
        assert_eq!(
            trace.denominator_completeness,
            CoverageCompleteness::Partial
        );
        assert!(!absence_claim_admissible(&manifest, "host.shell"));
        assert!(coverage_percentage(&manifest, 3, 4).is_none());
    }

    #[test]
    fn pass_requires_complete_denominator() {
        let manifest = complete_manifest();
        let mut trace = derive_compliance_trace(&manifest, &clean_evidence());
        assert_eq!(trace.disposition, ComplianceDisposition::Pass);
        assert!(trace.validate().is_ok());
        trace.denominator_completeness = CoverageCompleteness::Partial;
        assert!(trace.validate().is_err());
    }
}
