//! Asymmetric bootstrap for verification-surface self-changes (I18.31).
//!
//! A changed verifier cannot be the sole authority proving its own
//! correctness. Every change to the listed verification/control surface
//! passes five phases: a last-known-good runner/harness runs the unchanged
//! external discriminator plus the candidate contract suite; the candidate
//! processes the same raw fixture/tool evidence in shadow; comparison
//! checks raw capture, normalized meaning, selection, omissions, and
//! outcome; canary runs bounded real tasks while the old generation stays
//! rollback-capable; cutover happens only on independent evidence plus a
//! new generation receipt.
//!
//! This module is pure planning/authority semantics: it records phase
//! transitions and receipts but performs no process, filesystem, or
//! network effects. The Governor owns these semantics; the Kernel owns
//! admission/fencing effects at its own enforcement points.

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Stable identity of the self-change bootstrap contract.
pub const CONTRACT_NAME: &str = "eliot.instrument.verifier.self-change";
/// Wire revision of the bootstrap contract.
pub const CONTRACT_VERSION: (u16, u16, u16) = (1, 0, 0);

/// Upper bound on canary real tasks. A canary is bounded by construction.
pub const MAX_CANARY_TASKS: u32 = 1024;

/// The changed verification/control surface, and nothing else (I18.31 W5).
///
/// The protocol binds only the admitted surface; unrelated modules ship
/// normally and never pass through this machine.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfChangeSurface {
    /// `ProcessExecutor` implementation or launch semantics.
    ProcessExecutor,
    /// `InstrumentRunner` orchestration.
    InstrumentRunner,
    /// Profile/test selection and impact analysis.
    ProfileSelection,
    /// Evidence parsers.
    Parser,
    /// Evidence normalization.
    EvidenceNormalization,
    /// Test discovery.
    TestDiscovery,
    /// `FinishService` and verifier binding.
    FinishService,
}

impl SelfChangeSurface {
    /// Every surface governed by the bootstrap.
    pub const ALL: [Self; 7] = [
        Self::ProcessExecutor,
        Self::InstrumentRunner,
        Self::ProfileSelection,
        Self::Parser,
        Self::EvidenceNormalization,
        Self::TestDiscovery,
        Self::FinishService,
    ];

    /// Stable wire name of the surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessExecutor => "process-executor",
            Self::InstrumentRunner => "instrument-runner",
            Self::ProfileSelection => "profile-selection",
            Self::Parser => "parser",
            Self::EvidenceNormalization => "evidence-normalization",
            Self::TestDiscovery => "test-discovery",
            Self::FinishService => "finish-service",
        }
    }

    /// The I18.31 special case this surface change must satisfy, if any.
    #[must_use]
    pub const fn special_case(self) -> Option<SpecialCase> {
        match self {
            Self::ProcessExecutor => Some(SpecialCase::ExecutorOuterGuardian),
            Self::Parser => Some(SpecialCase::ParserReplay),
            Self::ProfileSelection => Some(SpecialCase::SelectionSentinel),
            Self::FinishService => Some(SpecialCase::FinishServiceAdversarial),
            Self::InstrumentRunner | Self::EvidenceNormalization | Self::TestDiscovery => None,
        }
    }
}

/// The four I18.31 special cases (W2).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialCase {
    /// A `ProcessExecutor` change needs an outer Host/OS guardian scenario
    /// verifying tree cleanup and evidence.
    ExecutorOuterGuardian,
    /// A parser change replays the old raw corpus through old and
    /// candidate parsers.
    ParserReplay,
    /// A selection/impact change runs historical escapes plus sentinel
    /// lanes for false negatives.
    SelectionSentinel,
    /// A `FinishService`/verifier-binding change runs the forged/partial-proof
    /// adversarial suite through the last-known-good public front door.
    FinishServiceAdversarial,
}

impl SpecialCase {
    /// Stable wire name of the special case.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecutorOuterGuardian => "executor-outer-guardian",
            Self::ParserReplay => "parser-replay",
            Self::SelectionSentinel => "selection-sentinel",
            Self::FinishServiceAdversarial => "finish-service-adversarial",
        }
    }

    /// The surface this special case guards.
    #[must_use]
    pub const fn surface(self) -> SelfChangeSurface {
        match self {
            Self::ExecutorOuterGuardian => SelfChangeSurface::ProcessExecutor,
            Self::ParserReplay => SelfChangeSurface::Parser,
            Self::SelectionSentinel => SelfChangeSurface::ProfileSelection,
            Self::FinishServiceAdversarial => SelfChangeSurface::FinishService,
        }
    }

    /// Verifies typed special-case evidence with this case's mechanic.
    ///
    /// Each arm calls the real check: the executor arm re-checks the
    /// outer-guardian digest half over the exact evidence bytes, the parser
    /// arm replays the bound corpus, the selection arm requires zero false
    /// negatives with lane coverage, and the finish arm requires every
    /// forged and partial proof rejected.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::UnexpectedSpecialCase`] when the evidence
    /// belongs to another case, or the mechanic's typed error on divergence.
    pub fn verify(&self, evidence: &SpecialCaseEvidence) -> Result<(), SelfChangeError> {
        match (self, evidence) {
            (Self::ExecutorOuterGuardian, SpecialCaseEvidence::ExecutorOuterGuardian(record)) => {
                verify_outer_guardian_record(record)
            }
            (Self::ParserReplay, SpecialCaseEvidence::ParserReplay(record)) => {
                verify_parser_replay(record)
            }
            (Self::SelectionSentinel, SpecialCaseEvidence::SelectionSentinel(record)) => {
                verify_selection_sentinel(record)
            }
            (
                Self::FinishServiceAdversarial,
                SpecialCaseEvidence::FinishServiceAdversarial(record),
            ) => verify_finish_adversarial(record),
            (_, mismatched) => Err(SelfChangeError::UnexpectedSpecialCase {
                observed: mismatched.case(),
            }),
        }
    }
}

/// Typed evidence admitted by [`SpecialCase::verify`], one variant per case.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialCaseEvidence {
    /// Outer guardian scenario evidence for a `ProcessExecutor` change.
    ExecutorOuterGuardian(OuterGuardianRecord),
    /// Old-corpus replay for a parser change.
    ParserReplay(ParserReplayRecord),
    /// Historical escapes plus sentinel lanes for a selection change.
    SelectionSentinel(SelectionSentinelRecord),
    /// Forged/partial-proof suite for a `FinishService` change.
    FinishServiceAdversarial(AdversarialSuiteRecord),
}

impl SpecialCaseEvidence {
    /// The special case this evidence belongs to.
    #[must_use]
    pub const fn case(&self) -> SpecialCase {
        match self {
            Self::ExecutorOuterGuardian(_) => SpecialCase::ExecutorOuterGuardian,
            Self::ParserReplay(_) => SpecialCase::ParserReplay,
            Self::SelectionSentinel(_) => SpecialCase::SelectionSentinel,
            Self::FinishServiceAdversarial(_) => SpecialCase::FinishServiceAdversarial,
        }
    }
}

/// Verifier-side admission record for one outer guardian scenario.
///
/// The existing mechanic (`eliot-process-executor` `verify_outer_guardian`)
/// proves the scenario worktree absent-or-empty from the machine; that
/// filesystem proof runs at the Kernel composition root, which owns both
/// crates, because this module performs no filesystem effects. The root runs
/// the existing verify, then presents the exact evidence bytes plus the
/// observed cleanup outcome here, where [`verify_outer_guardian_record`]
/// re-checks the digest half and admits only an attested cleaned tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OuterGuardianRecord {
    /// The exact scenario evidence bytes, re-hashed on verify.
    pub evidence_bytes: Vec<u8>,
    /// The expected digest the recomputed value must equal.
    pub expected_evidence: EvidenceDigest,
    /// Whether the existing `verify_outer_guardian` observed the scenario
    /// worktree absent or emptied.
    pub tree_cleaned: bool,
}

/// Re-checks one outer guardian scenario admission.
///
/// Recomputes the SHA-256 digest over the exact evidence bytes and requires
/// the attested cleaned tree observed by the existing
/// `verify_outer_guardian` at the composition root.
///
/// # Errors
///
/// Returns [`SelfChangeError::GuardianEvidenceMismatch`] on digest drift or
/// [`SelfChangeError::GuardianTreeNotCleaned`] without the attested cleanup.
pub fn verify_outer_guardian_record(record: &OuterGuardianRecord) -> Result<(), SelfChangeError> {
    let observed = eliot_contracts::sha256_hex(&record.evidence_bytes);
    if observed != record.expected_evidence.as_str() {
        return Err(SelfChangeError::GuardianEvidenceMismatch);
    }
    if !record.tree_cleaned {
        return Err(SelfChangeError::GuardianTreeNotCleaned);
    }
    Ok(())
}

/// One parser output side: raw capture plus normalized meaning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParserOutput {
    /// Raw capture bytes emitted by the parser.
    pub raw_capture: Vec<u8>,
    /// Normalized meaning extracted from the raw capture.
    pub normalized_meaning: String,
}

/// Old-corpus replay through old and candidate parsers (I18.31 W2).
///
/// Outputs pair item by item in corpus order: `old_output[i]` and
/// `candidate_output[i]` parsed the same corpus item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParserReplayRecord {
    /// Digest binding the replayed old raw corpus.
    pub corpus: EvidenceDigest,
    /// Old-parser outputs in corpus order.
    pub old_output: Vec<ParserOutput>,
    /// Candidate-parser outputs in corpus order.
    pub candidate_output: Vec<ParserOutput>,
}

impl ParserReplayRecord {
    /// Records one replay. Outputs must pair item by item over a non-empty
    /// corpus.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::ParserCorpusEmpty`] for an empty corpus or
    /// [`SelfChangeError::ParserReplayLengthMismatch`] when the sides do not
    /// pair.
    pub fn new(
        corpus: EvidenceDigest,
        old_output: Vec<ParserOutput>,
        candidate_output: Vec<ParserOutput>,
    ) -> Result<Self, SelfChangeError> {
        if old_output.is_empty() {
            return Err(SelfChangeError::ParserCorpusEmpty);
        }
        if old_output.len() != candidate_output.len() {
            return Err(SelfChangeError::ParserReplayLengthMismatch {
                old: old_output.len(),
                candidate: candidate_output.len(),
            });
        }
        Ok(Self {
            corpus,
            old_output,
            candidate_output,
        })
    }
}

/// Verifies one parser replay.
///
/// The old outputs re-hash to the bound corpus digest (corpus-scoped: no
/// item added, dropped, or swapped passes), then every paired item must
/// match on [`ComparisonAxis::RawCapture`] and
/// [`ComparisonAxis::NormalizedMeaning`].
///
/// # Errors
///
/// Returns [`SelfChangeError::ParserCorpusEmpty`],
/// [`SelfChangeError::ParserReplayLengthMismatch`],
/// [`SelfChangeError::ParserCorpusMismatch`], or
/// [`SelfChangeError::ParserReplayDiverged`].
pub fn verify_parser_replay(record: &ParserReplayRecord) -> Result<(), SelfChangeError> {
    if record.old_output.is_empty() {
        return Err(SelfChangeError::ParserCorpusEmpty);
    }
    if record.old_output.len() != record.candidate_output.len() {
        return Err(SelfChangeError::ParserReplayLengthMismatch {
            old: record.old_output.len(),
            candidate: record.candidate_output.len(),
        });
    }
    let mut bound = Vec::new();
    for output in &record.old_output {
        bound.extend_from_slice(&output.raw_capture.len().to_be_bytes());
        bound.extend_from_slice(&output.raw_capture);
    }
    if eliot_contracts::sha256_hex(&bound) != record.corpus.as_str() {
        return Err(SelfChangeError::ParserCorpusMismatch);
    }
    for (index, pair) in record
        .old_output
        .iter()
        .zip(record.candidate_output.iter())
        .enumerate()
    {
        let (old, candidate) = pair;
        let mut axes = Vec::new();
        if old.raw_capture != candidate.raw_capture {
            axes.push(ComparisonAxis::RawCapture);
        }
        if old.normalized_meaning != candidate.normalized_meaning {
            axes.push(ComparisonAxis::NormalizedMeaning);
        }
        if !axes.is_empty() {
            return Err(SelfChangeError::ParserReplayDiverged { index, axes });
        }
    }
    Ok(())
}

/// Selection outcome for one sentinel case.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionOutcome {
    /// The candidate selection picked the case.
    Selected,
    /// The candidate selection dropped the case: a false negative.
    Missed,
}

/// One historical escape or sentinel-lane probe with its outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SentinelCase {
    /// Stable case identity.
    pub case_id: String,
    /// Sentinel lane the case probes.
    pub lane: String,
    /// Whether this case escaped selection historically.
    pub historical_escape: bool,
    /// Outcome under the candidate selection.
    pub outcome: SelectionOutcome,
}

impl SentinelCase {
    /// Declares one sentinel case. Identity and lane must be text.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::InvalidText`] for a blank case id or lane.
    pub fn new(
        case_id: impl Into<String>,
        lane: impl Into<String>,
        historical_escape: bool,
        outcome: SelectionOutcome,
    ) -> Result<Self, SelfChangeError> {
        let case_id = case_id.into();
        if case_id.trim().is_empty() || case_id.chars().any(char::is_control) {
            return Err(SelfChangeError::InvalidText { field: "case_id" });
        }
        let lane = lane.into();
        if lane.trim().is_empty() || lane.chars().any(char::is_control) {
            return Err(SelfChangeError::InvalidText { field: "lane" });
        }
        Ok(Self {
            case_id,
            lane,
            historical_escape,
            outcome,
        })
    }

    /// Whether the candidate selection missed this must-select case.
    #[must_use]
    pub const fn is_false_negative(&self) -> bool {
        matches!(self.outcome, SelectionOutcome::Missed)
    }
}

/// Historical escapes plus sentinel lanes for a selection/impact change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SelectionSentinelRecord {
    /// Lanes that must each hold at least one case.
    pub required_lanes: Vec<String>,
    /// Historical escapes and sentinel-lane probes with outcomes.
    pub cases: Vec<SentinelCase>,
}

impl SelectionSentinelRecord {
    /// Records one sentinel run. At least one lane is required.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::SelectionNoSentinelLanes`] without lanes
    /// or [`SelfChangeError::InvalidText`] for a blank lane.
    pub fn new(
        required_lanes: Vec<String>,
        cases: Vec<SentinelCase>,
    ) -> Result<Self, SelfChangeError> {
        if required_lanes.is_empty() {
            return Err(SelfChangeError::SelectionNoSentinelLanes);
        }
        for lane in &required_lanes {
            if lane.trim().is_empty() || lane.chars().any(char::is_control) {
                return Err(SelfChangeError::InvalidText { field: "lane" });
            }
        }
        Ok(Self {
            required_lanes,
            cases,
        })
    }
}

/// Verifies one selection sentinel record: every required lane must hold at
/// least one case, and every case must be selected — zero false negatives.
/// Historical escapes carry no weaker rule: any miss fails closed.
///
/// # Errors
///
/// Returns [`SelfChangeError::SelectionNoSentinelLanes`],
/// [`SelfChangeError::SelectionLaneUncovered`], or
/// [`SelfChangeError::SelectionFalseNegative`].
pub fn verify_selection_sentinel(record: &SelectionSentinelRecord) -> Result<(), SelfChangeError> {
    if record.required_lanes.is_empty() {
        return Err(SelfChangeError::SelectionNoSentinelLanes);
    }
    for lane in &record.required_lanes {
        if !record.cases.iter().any(|case| &case.lane == lane) {
            return Err(SelfChangeError::SelectionLaneUncovered { lane: lane.clone() });
        }
    }
    for case in &record.cases {
        if case.is_false_negative() {
            return Err(SelfChangeError::SelectionFalseNegative {
                case: case.case_id.clone(),
            });
        }
    }
    Ok(())
}

/// Proof strength of one adversarial suite case.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialProof {
    /// Forged proof: the front door must reject it.
    Forged,
    /// Partial proof: the front door must reject it.
    Partial,
}

/// Last-known-good public front-door verdict for one suite case.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontDoorVerdict {
    /// The front door admitted the case.
    Admitted,
    /// The front door rejected the case.
    Rejected,
}

/// One forged/partial-proof case with its front-door verdict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdversarialCase {
    /// Stable case identity.
    pub case_id: String,
    /// Proof strength under attack.
    pub proof: AdversarialProof,
    /// Verdict from the last-known-good public front door.
    pub verdict: FrontDoorVerdict,
}

impl AdversarialCase {
    /// Declares one adversarial case. Identity must be text.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::InvalidText`] for a blank case id.
    pub fn new(
        case_id: impl Into<String>,
        proof: AdversarialProof,
        verdict: FrontDoorVerdict,
    ) -> Result<Self, SelfChangeError> {
        let case_id = case_id.into();
        if case_id.trim().is_empty() || case_id.chars().any(char::is_control) {
            return Err(SelfChangeError::InvalidText { field: "case_id" });
        }
        Ok(Self {
            case_id,
            proof,
            verdict,
        })
    }
}

/// Forged/partial-proof adversarial suite through the last-known-good public
/// front door (I18.31 W2).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdversarialSuiteRecord {
    /// Suite cases with their front-door verdicts.
    pub cases: Vec<AdversarialCase>,
}

impl AdversarialSuiteRecord {
    /// Records one suite run. The suite must hold at least one case.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::AdversarialSuiteEmpty`] for an empty suite.
    pub fn new(cases: Vec<AdversarialCase>) -> Result<Self, SelfChangeError> {
        if cases.is_empty() {
            return Err(SelfChangeError::AdversarialSuiteEmpty);
        }
        Ok(Self { cases })
    }
}

/// Verifies one adversarial suite: the suite must hold at least one forged
/// case, and the front door must reject every forged and every partial case
/// — all forged rejected, no partial admitted.
///
/// # Errors
///
/// Returns [`SelfChangeError::AdversarialSuiteEmpty`],
/// [`SelfChangeError::AdversarialNoForgedCase`],
/// [`SelfChangeError::AdversarialForgedAdmitted`], or
/// [`SelfChangeError::AdversarialPartialAdmitted`].
pub fn verify_finish_adversarial(record: &AdversarialSuiteRecord) -> Result<(), SelfChangeError> {
    if record.cases.is_empty() {
        return Err(SelfChangeError::AdversarialSuiteEmpty);
    }
    if !record
        .cases
        .iter()
        .any(|case| matches!(case.proof, AdversarialProof::Forged))
    {
        return Err(SelfChangeError::AdversarialNoForgedCase);
    }
    for case in &record.cases {
        if matches!(case.verdict, FrontDoorVerdict::Admitted) {
            match case.proof {
                AdversarialProof::Forged => {
                    return Err(SelfChangeError::AdversarialForgedAdmitted {
                        case: case.case_id.clone(),
                    });
                }
                AdversarialProof::Partial => {
                    return Err(SelfChangeError::AdversarialPartialAdmitted {
                        case: case.case_id.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// The five I18.31 bootstrap phases, in cutover order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapPhase {
    /// Last-known-good runner/harness runs the unchanged external
    /// discriminator plus the candidate contract suite.
    LastKnownGood,
    /// The candidate processes the same raw fixture/tool evidence in shadow.
    Shadow,
    /// Comparison checks every [`ComparisonAxis`].
    Comparison,
    /// Bounded real tasks run while the old generation stays
    /// rollback-capable.
    Canary,
    /// Terminal phase: independent evidence plus a new generation receipt.
    Cutover,
}

/// One comparison axis checked between shadow and last-known-good.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonAxis {
    /// Raw capture bytes.
    RawCapture,
    /// Normalized meaning.
    NormalizedMeaning,
    /// Selection decisions.
    Selection,
    /// Omissions.
    Omissions,
    /// Outcome.
    Outcome,
}

impl ComparisonAxis {
    /// Every axis a comparison must cover.
    pub const ALL: [Self; 5] = [
        Self::RawCapture,
        Self::NormalizedMeaning,
        Self::Selection,
        Self::Omissions,
        Self::Outcome,
    ];
}

/// Validated lowercase SHA-256 hex digest identifying bootstrap evidence.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EvidenceDigest(String);

impl EvidenceDigest {
    /// Validates a digest handle.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::InvalidDigest`] unless the value is
    /// exactly 64 lowercase hex characters.
    pub fn new(digest: impl Into<String>) -> Result<Self, SelfChangeError> {
        let digest = digest.into();
        let valid = digest.len() == 64
            && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            && digest.bytes().all(|byte| !byte.is_ascii_uppercase());
        if valid {
            Ok(Self(digest))
        } else {
            Err(SelfChangeError::InvalidDigest)
        }
    }

    /// Returns the validated digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for EvidenceDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EvidenceDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Per-axis shadow comparison verdicts, recorded as divergence.
///
/// An empty list means every axis in [`ComparisonAxis::ALL`] matches; a
/// non-empty list names exactly the diverging axes in canonical order.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AxisVerdicts {
    /// The diverging axes, in canonical order.
    pub diverged: Vec<ComparisonAxis>,
}

impl AxisVerdicts {
    /// Verdicts for one fully matching comparison.
    #[must_use]
    pub fn all_matched() -> Self {
        Self {
            diverged: Vec::new(),
        }
    }

    /// Verdicts diverging exactly on `axes`, stored in canonical order.
    #[must_use]
    pub fn with_divergence(axes: impl Into<Vec<ComparisonAxis>>) -> Self {
        let mut diverged = axes.into();
        diverged.sort();
        diverged.dedup();
        Self { diverged }
    }

    /// Whether every axis matches.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.diverged.is_empty()
    }

    /// The diverging axes, in canonical order.
    #[must_use]
    pub fn diverged_axes(&self) -> Vec<ComparisonAxis> {
        self.diverged.clone()
    }

    /// Whether one axis matches.
    #[must_use]
    pub fn matches(&self, axis: ComparisonAxis) -> bool {
        !self.diverged.contains(&axis)
    }
}

/// Shadow comparison record over the same raw fixture/tool evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShadowComparisonRecord {
    /// The changed surface under comparison (W5 scope).
    pub surface: SelfChangeSurface,
    /// Old generation producing the reference side.
    pub old_generation: u64,
    /// Candidate generation producing the shadow side.
    pub candidate_generation: u64,
    /// Per-axis verdicts.
    pub verdicts: AxisVerdicts,
    /// Digest of the comparison evidence.
    pub evidence: EvidenceDigest,
}

impl ShadowComparisonRecord {
    /// Records one comparison. Generations must advance.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::NonAdvancingGeneration`] when the
    /// candidate does not advance past the old generation.
    pub fn new(
        surface: SelfChangeSurface,
        old_generation: u64,
        candidate_generation: u64,
        verdicts: AxisVerdicts,
        evidence: EvidenceDigest,
    ) -> Result<Self, SelfChangeError> {
        if candidate_generation <= old_generation {
            return Err(SelfChangeError::NonAdvancingGeneration {
                old: old_generation,
                candidate: candidate_generation,
            });
        }
        Ok(Self {
            surface,
            old_generation,
            candidate_generation,
            verdicts,
            evidence,
        })
    }

    /// Whether every comparison axis matches.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.verdicts.is_clean()
    }
}

/// Canary record: bounded real tasks with the old generation rollback-capable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanaryRecord {
    /// The changed surface under canary (W5 scope).
    pub surface: SelfChangeSurface,
    /// Old generation kept rollback-capable.
    pub old_generation: u64,
    /// Candidate generation under canary.
    pub candidate_generation: u64,
    /// Number of real canary tasks, within `1..=MAX_CANARY_TASKS`.
    pub bounded_tasks: u32,
    /// Whether rollback to the old generation was demonstrated capable.
    pub rollback_capable: bool,
    /// Digest of the canary evidence.
    pub evidence: EvidenceDigest,
}

impl CanaryRecord {
    /// Records one canary. The task count must be bounded and nonzero.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::NonAdvancingGeneration`] when the
    /// candidate does not advance, or [`SelfChangeError::CanaryTaskBound`]
    /// when the task count is zero or above [`MAX_CANARY_TASKS`].
    pub fn new(
        surface: SelfChangeSurface,
        old_generation: u64,
        candidate_generation: u64,
        bounded_tasks: u32,
        rollback_capable: bool,
        evidence: EvidenceDigest,
    ) -> Result<Self, SelfChangeError> {
        if candidate_generation <= old_generation {
            return Err(SelfChangeError::NonAdvancingGeneration {
                old: old_generation,
                candidate: candidate_generation,
            });
        }
        if bounded_tasks == 0 || bounded_tasks > MAX_CANARY_TASKS {
            return Err(SelfChangeError::CanaryTaskBound { bounded_tasks });
        }
        Ok(Self {
            surface,
            old_generation,
            candidate_generation,
            bounded_tasks,
            rollback_capable,
            evidence,
        })
    }

    /// Whether the canary permits cutover: bounded tasks ran and rollback
    /// to the old generation was demonstrated capable.
    #[must_use]
    pub const fn is_cutover_ready(&self) -> bool {
        self.rollback_capable && self.bounded_tasks > 0
    }
}

/// Generation receipt minted only by [`SelfChangeBootstrap::cutover`].
///
/// This is the I18.31 bootstrap receipt for one verification-surface
/// change, not the Kernel/ORS `GenerationCutoverReceipt` for module route
/// cutover (I14.14). Fields are private so a receipt can never be
/// hand-built: it exists only after the full phase sequence with
/// independent evidence. Deserialized receipts are evidence for
/// transfer; strict entries currently check surface scope only, and
/// receipt-chain revalidation awaits its owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenerationReceipt {
    surface: SelfChangeSurface,
    old_generation: u64,
    new_generation: u64,
    comparison: EvidenceDigest,
    canary: EvidenceDigest,
    special_case: Option<(SpecialCase, EvidenceDigest)>,
}

impl GenerationReceipt {
    /// The changed surface this receipt covers (W5 scope).
    #[must_use]
    pub const fn surface(&self) -> SelfChangeSurface {
        self.surface
    }

    /// Whether this receipt covers `surface` and no other.
    #[must_use]
    pub fn covers(&self, surface: SelfChangeSurface) -> bool {
        self.surface == surface
    }

    /// Retired old generation.
    #[must_use]
    pub const fn old_generation(&self) -> u64 {
        self.old_generation
    }

    /// Admitted new generation.
    #[must_use]
    pub const fn new_generation(&self) -> u64 {
        self.new_generation
    }

    /// Digest of the clean shadow comparison evidence.
    #[must_use]
    pub const fn comparison(&self) -> &EvidenceDigest {
        &self.comparison
    }

    /// Digest of the rollback-capable canary evidence.
    #[must_use]
    pub const fn canary(&self) -> &EvidenceDigest {
        &self.canary
    }

    /// Special-case evidence, present exactly when the surface requires one.
    #[must_use]
    pub fn special_case(&self) -> Option<&(SpecialCase, EvidenceDigest)> {
        self.special_case.as_ref()
    }
}

/// Unresolved oracle conflict between the old generation and a candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleConflict {
    /// The changed surface under dispute.
    pub surface: SelfChangeSurface,
    /// Old generation raising the dispute.
    pub old_generation: u64,
    /// Candidate generation under dispute.
    pub candidate_generation: u64,
    /// Non-blank conflict detail.
    pub detail: String,
}

impl OracleConflict {
    /// Declares one conflict. Generations must advance; detail must be text.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::NonAdvancingGeneration`] or
    /// [`SelfChangeError::InvalidText`] for malformed input.
    pub fn new(
        surface: SelfChangeSurface,
        old_generation: u64,
        candidate_generation: u64,
        detail: impl Into<String>,
    ) -> Result<Self, SelfChangeError> {
        if candidate_generation <= old_generation {
            return Err(SelfChangeError::NonAdvancingGeneration {
                old: old_generation,
                candidate: candidate_generation,
            });
        }
        let detail = detail.into();
        if detail.trim().is_empty() || detail.chars().any(char::is_control) {
            return Err(SelfChangeError::InvalidText { field: "detail" });
        }
        Ok(Self {
            surface,
            old_generation,
            candidate_generation,
            detail,
        })
    }

    /// The old generation rejects the candidate. Rejection is the only
    /// unilateral old-generation power.
    #[must_use]
    pub fn reject(&self, reason: impl Into<String>) -> OracleResolution {
        OracleResolution::RejectedByOldGeneration {
            reason: reason.into(),
        }
    }

    /// Escalates the unresolved conflict to a Human or independent route,
    /// which alone decides. There is deliberately no outcome in which the
    /// old generation certifies itself permanently correct.
    #[must_use]
    pub const fn escalate(&self, to: ConflictArbiter) -> OracleResolution {
        OracleResolution::Escalated { to }
    }
}

/// Who decides an unresolved oracle conflict (W3).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictArbiter {
    /// A Human decides.
    Human,
    /// An independent route decides.
    IndependentRoute(String),
}

impl ConflictArbiter {
    /// Names one independent route. The route must be non-blank text.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::InvalidText`] for blank input.
    pub fn independent_route(route: impl Into<String>) -> Result<Self, SelfChangeError> {
        let route = route.into();
        if route.trim().is_empty() || route.chars().any(char::is_control) {
            return Err(SelfChangeError::InvalidText { field: "route" });
        }
        Ok(Self::IndependentRoute(route))
    }
}

/// Resolution of an [`OracleConflict`].
///
/// The two outcomes are exhaustive: rejection by the old generation, or
/// escalation to a Human/independent route. Permanent self-certification
/// by the old generation is not representable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleResolution {
    /// The old generation rejected the candidate.
    RejectedByOldGeneration {
        /// Recorded rejection reason.
        reason: String,
    },
    /// A Human or independent route decides the unresolved conflict.
    Escalated {
        /// The deciding arbiter.
        to: ConflictArbiter,
    },
}

/// Failures raised while admitting or advancing a self-change bootstrap.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SelfChangeError {
    /// An evidence digest is not 64 lowercase hex characters.
    #[error("bootstrap evidence digest must be 64 lowercase hex characters")]
    InvalidDigest,
    /// The candidate generation does not advance past the old one.
    #[error("candidate generation {candidate} must advance past old generation {old}")]
    NonAdvancingGeneration {
        /// Old generation.
        old: u64,
        /// Candidate generation.
        candidate: u64,
    },
    /// Evidence arrived for a phase that is not open.
    #[error("bootstrap phase must be {expected:?}, observed {observed:?}")]
    PhaseOrder {
        /// The open phase.
        expected: BootstrapPhase,
        /// The phase the evidence belongs to.
        observed: BootstrapPhase,
    },
    /// Evidence names a surface outside the admitted scope (W5).
    #[error("bootstrap covers {expected:?}, not {observed:?}")]
    SurfaceMismatch {
        /// The admitted surface.
        expected: SelfChangeSurface,
        /// The observed surface.
        observed: SelfChangeSurface,
    },
    /// Evidence names generations outside the admitted pair.
    #[error("bootstrap covers generations {expected_old}->{expected_candidate}")]
    GenerationMismatch {
        /// The admitted old generation.
        expected_old: u64,
        /// The admitted candidate generation.
        expected_candidate: u64,
    },
    /// Shadow comparison diverges on at least one axis.
    #[error("shadow comparison diverges")]
    ComparisonDiverged {
        /// The diverging axes.
        axes: Vec<ComparisonAxis>,
    },
    /// The canary task count is zero or above [`MAX_CANARY_TASKS`].
    #[error("canary task count {bounded_tasks} is not within 1..=1024")]
    CanaryTaskBound {
        /// The observed task count.
        bounded_tasks: u32,
    },
    /// Rollback to the old generation was not demonstrated capable.
    #[error("canary rollback to the old generation is not demonstrated capable")]
    CanaryRollbackIncapable,
    /// The surface requires a special case whose evidence is missing.
    #[error("special case {case:?} evidence is missing")]
    SpecialCaseMissing {
        /// The required special case.
        case: SpecialCase,
    },
    /// Special-case evidence names the wrong case for the surface.
    #[error("special case {observed:?} does not guard this surface")]
    UnexpectedSpecialCase {
        /// The observed special case.
        observed: SpecialCase,
    },
    /// Special-case evidence was already recorded.
    #[error("special case evidence is already recorded")]
    DuplicateSpecialCase,
    /// The recomputed guardian evidence digest differs from the expected value.
    #[error("guardian evidence digest does not match the expected value")]
    GuardianEvidenceMismatch,
    /// The outer guardian did not observe a cleaned scenario worktree.
    #[error("guardian scenario worktree is not attested cleaned")]
    GuardianTreeNotCleaned,
    /// A parser replay names an empty old corpus.
    #[error("parser replay corpus is empty")]
    ParserCorpusEmpty,
    /// Old and candidate parser outputs do not pair item by item.
    #[error("parser replay pairs {old} old outputs with {candidate} candidate outputs")]
    ParserReplayLengthMismatch {
        /// Old-parser output count.
        old: usize,
        /// Candidate-parser output count.
        candidate: usize,
    },
    /// The old parser outputs do not re-hash to the bound corpus digest.
    #[error("parser replay outputs do not match the bound corpus digest")]
    ParserCorpusMismatch,
    /// One replayed item diverges between old and candidate parsers.
    #[error("parser replay item {index} diverges")]
    ParserReplayDiverged {
        /// The diverging corpus item index.
        index: usize,
        /// The diverging axes.
        axes: Vec<ComparisonAxis>,
    },
    /// A selection sentinel record names no required lanes.
    #[error("selection sentinel record names no required lanes")]
    SelectionNoSentinelLanes,
    /// A required sentinel lane holds no case.
    #[error("sentinel lane {lane} holds no case")]
    SelectionLaneUncovered {
        /// The uncovered lane.
        lane: String,
    },
    /// The candidate selection missed a must-select case.
    #[error("selection missed must-select case {case}")]
    SelectionFalseNegative {
        /// The missed case.
        case: String,
    },
    /// A finish adversarial suite holds no case.
    #[error("finish adversarial suite is empty")]
    AdversarialSuiteEmpty,
    /// A finish adversarial suite holds no forged case.
    #[error("finish adversarial suite holds no forged case")]
    AdversarialNoForgedCase,
    /// The front door admitted a forged proof.
    #[error("front door admitted forged case {case}")]
    AdversarialForgedAdmitted {
        /// The admitted forged case.
        case: String,
    },
    /// The front door admitted a partial proof.
    #[error("front door admitted partial-proof case {case}")]
    AdversarialPartialAdmitted {
        /// The admitted partial-proof case.
        case: String,
    },
    /// A text field is blank or carries control characters.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// The offending field.
        field: &'static str,
    },
    /// The finish-gate verdict behind a bootstrapped admission failed.
    #[error(transparent)]
    Verdict(#[from] super::VerifierError),
}

/// The I18.31 five-phase bootstrap machine for one surface change.
///
/// Created by [`SelfChangeBootstrap::admit`], advanced one phase at a time,
/// and consumed by [`SelfChangeBootstrap::cutover`]. Every transition
/// fails closed on out-of-order, out-of-scope, or insufficient evidence.
#[derive(Clone, Debug)]
pub struct SelfChangeBootstrap {
    surface: SelfChangeSurface,
    old_generation: u64,
    candidate_generation: u64,
    phase: BootstrapPhase,
    last_known_good: Option<EvidenceDigest>,
    shadow: Option<EvidenceDigest>,
    comparison: Option<ShadowComparisonRecord>,
    canary: Option<CanaryRecord>,
    special_case: Option<(SpecialCase, EvidenceDigest)>,
}

impl SelfChangeBootstrap {
    /// Admits one surface change into the bootstrap. The candidate
    /// generation must advance past the old generation.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::NonAdvancingGeneration`] when the
    /// candidate does not advance.
    pub fn admit(
        surface: SelfChangeSurface,
        old_generation: u64,
        candidate_generation: u64,
    ) -> Result<Self, SelfChangeError> {
        if candidate_generation <= old_generation {
            return Err(SelfChangeError::NonAdvancingGeneration {
                old: old_generation,
                candidate: candidate_generation,
            });
        }
        Ok(Self {
            surface,
            old_generation,
            candidate_generation,
            phase: BootstrapPhase::LastKnownGood,
            last_known_good: None,
            shadow: None,
            comparison: None,
            canary: None,
            special_case: None,
        })
    }

    /// The admitted surface (W5 scope).
    #[must_use]
    pub const fn surface(&self) -> SelfChangeSurface {
        self.surface
    }

    /// The currently open phase.
    #[must_use]
    pub const fn phase(&self) -> BootstrapPhase {
        self.phase
    }

    /// Records last-known-good evidence: the unchanged external
    /// discriminator plus the candidate contract suite ran.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::PhaseOrder`] unless the last-known-good
    /// phase is open.
    pub fn record_last_known_good(
        &mut self,
        evidence: EvidenceDigest,
    ) -> Result<(), SelfChangeError> {
        self.require_phase(BootstrapPhase::LastKnownGood)?;
        self.last_known_good = Some(evidence);
        self.phase = BootstrapPhase::Shadow;
        Ok(())
    }

    /// Records shadow evidence: the candidate processed the same raw
    /// fixture/tool evidence in shadow.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::PhaseOrder`] unless the shadow phase is
    /// open.
    pub fn record_shadow(&mut self, evidence: EvidenceDigest) -> Result<(), SelfChangeError> {
        self.require_phase(BootstrapPhase::Shadow)?;
        self.shadow = Some(evidence);
        self.phase = BootstrapPhase::Comparison;
        Ok(())
    }

    /// Records the shadow comparison. It must be in scope, name the
    /// admitted generations, and match on every axis.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::PhaseOrder`], [`SelfChangeError::SurfaceMismatch`],
    /// [`SelfChangeError::GenerationMismatch`], or [`SelfChangeError::ComparisonDiverged`].
    pub fn record_comparison(
        &mut self,
        record: ShadowComparisonRecord,
    ) -> Result<(), SelfChangeError> {
        self.require_phase(BootstrapPhase::Comparison)?;
        self.require_scope(record.surface)?;
        self.require_generations(record.old_generation, record.candidate_generation)?;
        if !record.is_clean() {
            return Err(SelfChangeError::ComparisonDiverged {
                axes: record.verdicts.diverged_axes(),
            });
        }
        self.comparison = Some(record);
        self.phase = BootstrapPhase::Canary;
        Ok(())
    }

    /// Records the canary. It must be in scope, name the admitted
    /// generations, and demonstrate rollback capability.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::PhaseOrder`], [`SelfChangeError::SurfaceMismatch`],
    /// [`SelfChangeError::GenerationMismatch`], or [`SelfChangeError::CanaryRollbackIncapable`].
    pub fn record_canary(&mut self, record: CanaryRecord) -> Result<(), SelfChangeError> {
        self.require_phase(BootstrapPhase::Canary)?;
        self.require_scope(record.surface)?;
        self.require_generations(record.old_generation, record.candidate_generation)?;
        if !record.is_cutover_ready() {
            return Err(SelfChangeError::CanaryRollbackIncapable);
        }
        self.canary = Some(record);
        Ok(())
    }

    /// Records special-case evidence (W2). Allowed once the comparison
    /// phase opens; the case must guard the admitted surface.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::PhaseOrder`], [`SelfChangeError::UnexpectedSpecialCase`],
    /// or [`SelfChangeError::DuplicateSpecialCase`].
    pub fn record_special_case(
        &mut self,
        case: SpecialCase,
        evidence: EvidenceDigest,
    ) -> Result<(), SelfChangeError> {
        if self.phase < BootstrapPhase::Comparison {
            return Err(SelfChangeError::PhaseOrder {
                expected: BootstrapPhase::Comparison,
                observed: self.phase,
            });
        }
        if case.surface() != self.surface {
            return Err(SelfChangeError::UnexpectedSpecialCase { observed: case });
        }
        if self.special_case.is_some() {
            return Err(SelfChangeError::DuplicateSpecialCase);
        }
        self.special_case = Some((case, evidence));
        Ok(())
    }

    /// Cuts over to the candidate generation, minting the generation
    /// receipt. Requires the full phase sequence, a rollback-capable
    /// canary, and special-case evidence when the surface requires it.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::PhaseOrder`] or [`SelfChangeError::SpecialCaseMissing`].
    pub fn cutover(self) -> Result<GenerationReceipt, SelfChangeError> {
        if self.phase != BootstrapPhase::Canary || self.canary.is_none() {
            return Err(SelfChangeError::PhaseOrder {
                expected: BootstrapPhase::Canary,
                observed: self.phase,
            });
        }
        if let Some(case) = self.surface.special_case()
            && self.special_case.is_none()
        {
            return Err(SelfChangeError::SpecialCaseMissing { case });
        }
        let Some(comparison) = self.comparison else {
            return Err(SelfChangeError::PhaseOrder {
                expected: BootstrapPhase::Canary,
                observed: self.phase,
            });
        };
        let Some(canary) = self.canary else {
            return Err(SelfChangeError::PhaseOrder {
                expected: BootstrapPhase::Canary,
                observed: self.phase,
            });
        };
        Ok(GenerationReceipt {
            surface: self.surface,
            old_generation: self.old_generation,
            new_generation: self.candidate_generation,
            comparison: comparison.evidence,
            canary: canary.evidence,
            special_case: self.special_case,
        })
    }

    fn require_phase(&self, expected: BootstrapPhase) -> Result<(), SelfChangeError> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(SelfChangeError::PhaseOrder {
                expected,
                observed: self.phase,
            })
        }
    }

    fn require_scope(&self, surface: SelfChangeSurface) -> Result<(), SelfChangeError> {
        if surface == self.surface {
            Ok(())
        } else {
            Err(SelfChangeError::SurfaceMismatch {
                expected: self.surface,
                observed: surface,
            })
        }
    }

    fn require_generations(&self, old: u64, candidate: u64) -> Result<(), SelfChangeError> {
        if old == self.old_generation && candidate == self.candidate_generation {
            Ok(())
        } else {
            Err(SelfChangeError::GenerationMismatch {
                expected_old: self.old_generation,
                expected_candidate: self.candidate_generation,
            })
        }
    }
}

/// Converts a completed run into the finish-gate decision under a
/// bootstrapped `FinishService`/verifier-binding change.
///
/// This is the strict `verdict` path for use while the finish surface
/// itself ships a new generation: the cutover receipt must cover
/// [`SelfChangeSurface::FinishService`], then the real
/// [`super::verdict`] decides. Unrelated verification work keeps using
/// [`super::verdict`] directly; the protocol binds only the changed
/// surface.
///
/// Residual: composition roots switch to this entry when they ship a new
/// verifier/finish generation; no caller migrates yet.
///
/// # Errors
///
/// Returns [`SelfChangeError::SurfaceMismatch`] when the receipt covers a
/// different surface, or the underlying [`super::VerifierError`] when the
/// run cannot take a verdict.
pub fn verdict_with_bootstrap(
    plan: &super::VerifierPlan,
    run: &super::VerificationRun,
    created_at: time::OffsetDateTime,
    receipt: &GenerationReceipt,
) -> Result<super::VerificationVerdict, SelfChangeError> {
    if !receipt.covers(SelfChangeSurface::FinishService) {
        return Err(SelfChangeError::SurfaceMismatch {
            expected: SelfChangeSurface::FinishService,
            observed: receipt.surface(),
        });
    }
    Ok(super::verdict(plan, run, created_at)?)
}
