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
        if self.accounted()? > self.received {
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

impl ObservationCoverageManifest {
    /// Validates the denominator shape. A `COMPLETE` denominator carries no
    /// blind intervals; anything else stays `PARTIAL`, `UNKNOWN`, or
    /// `NOT_APPLICABLE`. Sequence gaps and payload mutations must be localized
    /// to blind intervals so a derived trace can always name its blocker.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.fingerprint.validate()?;
        text(&self.allowed_manifest_digest, "manifest.allowed_manifest_digest")?;
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
        {
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
            ordered.sort();
            for pair in ordered.windows(2) {
                if pair[0].0 == pair[1].0 && pair[1].1 <= pair[0].2 {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "manifest.blind_intervals_and_missing_source_reasons",
                        reason: "blind intervals overlap and double-count one cursor",
                    });
                }
            }
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
        if self.completeness == CoverageCompleteness::Complete {
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

/// Manifest and evidence bound to one allowed Tool/Facet manifest revision.
///
/// The binding carries the independently resolved allowed-manifest digest
/// alongside the two objects and verifies, in one place, that both validate
/// and that both reference that exact revision for this run/attempt/route.
/// Validating two independent objects separately is not this join: only
/// [`derive_compliance_trace_checked`] derives a disposition from a bound
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
        text(
            allowed_manifest_digest,
            "inputs.allowed_manifest_digest",
        )?;
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
/// [`BoundComplianceInputs::bind`]; the derived trace is re-validated before
/// it is returned, so an invalid or unbound pair fails typed instead of
/// producing a valid `PASS`.
pub fn derive_compliance_trace_checked(
    inputs: &BoundComplianceInputs<'_>,
) -> Result<HostObservedComplianceTrace, EvaluationContractError> {
    let trace = derive_core(inputs.manifest, inputs.evidence);
    trace.validate()?;
    debug_assert_eq!(
        trace.permitted_manifest_digest, inputs.allowed_manifest_digest,
        "bound derivation must carry the allowed manifest revision",
    );
    Ok(trace)
}

/// Derives a [`HostObservedComplianceTrace`] only from immutable host/runtime
/// records joined to the permitted denominator.
///
/// Classification, in order: forbidden tool action yields `FAIL`;
/// undeclared or hidden access, out-of-namespace write, blind interval, or
/// cursor gap (sequence gaps and payload mutations) yields `TAINTED`;
/// received-but-unclassified events, uncovered material actions, or
/// missing-source reasons lower the denominator and yield `UNKNOWN`; a
/// non-complete denominator without a concrete taint signal yields `UNKNOWN`;
/// only a fully accounted complete denominator with no taint signal yields
/// `PASS`. The result always carries the explicit denominator including its
/// completeness and can never present a gapped or undeclared run as compliant
/// `PASS`. Callers join a validated manifest: sequence faults without
/// localized blind intervals are rejected by
/// [`ObservationCoverageManifest::validate`], so a trace derived from a valid
/// manifest always satisfies [`HostObservedComplianceTrace::validate`].
/// Production callers prefer [`derive_compliance_trace_checked`], which
/// additionally verifies the common allowed-manifest binding and fails typed.
#[must_use]
pub fn derive_compliance_trace(
    manifest: &ObservationCoverageManifest,
    evidence: &ImmutableHostEvidence,
) -> HostObservedComplianceTrace {
    derive_core(manifest, evidence)
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
/// complete denominator with continuous cursors, a consistent numerator, and
/// a caller total that equals the checked manifest received count; otherwise
/// returns `None`. A numerator above the denominator is inconsistent
/// evidence, never a valid claim above 100 %, and an arbitrary denominator
/// is refused even when `covered <= total` holds.
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
    if total != manifest.counts.received {
        return None;
    }
    if covered > total {
        return None;
    }
    Some((covered as f64 / total as f64) * 100.0)
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
            let expected = (index as u64).checked_add(1).ok_or(
                EvaluationContractError::InvalidInterval {
                    field: "trace_ledger.records.trace_version",
                },
            )?;
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
    /// version. An invalid trace is refused typed and retained nowhere.
    pub fn append(
        &mut self,
        trace: HostObservedComplianceTrace,
        source_dependencies: Vec<String>,
    ) -> Result<u64, EvaluationContractError> {
        trace.validate()?;
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

    /// Returns the latest applicable version for `fingerprint`, or `None`
    /// when no applicable version exists for it.
    #[must_use]
    pub fn current_for(
        &self,
        fingerprint: &RunFingerprint,
    ) -> Option<&VersionedComplianceTrace> {
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
        let trace = derive_compliance_trace(&manifest, &clean_evidence());
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
        let mut trace = derive_compliance_trace(&manifest, &clean_evidence());
        assert_eq!(trace.disposition, ComplianceDisposition::Pass);
        assert!(trace.validate().is_ok());
        trace.denominator_completeness = CoverageCompleteness::Partial;
        assert!(trace.validate().is_err());
    }
}
