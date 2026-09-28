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
//! The independent evidence a cutover requires is the machine-observed
//! program identity of the two passes. The shadow comparison carries both
//! observed program digests, and the bootstrap refuses a candidate that
//! observed the same program as the last-known-good generation: comparing one
//! implementation with itself matches every axis while proving nothing, which
//! is precisely the "changed verifier as sole authority" case the bootstrap
//! exists to refuse.
//!
//! Refusal is terminal under the oracle rule (W3): a refused cutover is
//! rejected by the old generation, and a diverged shadow comparison
//! escalates to a Human or independent route. The old generation can
//! reject a candidate but can never certify itself permanently correct.
//!
//! This module is pure planning/authority semantics: it records phase
//! transitions and receipts but performs no process, filesystem, or
//! network effects. The Governor owns these semantics; the Kernel owns
//! admission/fencing effects at its own enforcement points.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::sha256_hex;
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
    /// Documentation/audit tooling: the `DocumentationEvidenceCheck` freeze
    /// and publication path (I18.31:40, I0.14). A change to the tool that
    /// renders, packages or audits the documentation is a verification-surface
    /// change for the same reason a parser change is: it decides what evidence
    /// the rest of the system is allowed to believe.
    DocumentationTooling,
}

impl SelfChangeSurface {
    /// Every surface governed by the bootstrap.
    pub const ALL: [Self; 8] = [
        Self::ProcessExecutor,
        Self::InstrumentRunner,
        Self::ProfileSelection,
        Self::Parser,
        Self::EvidenceNormalization,
        Self::TestDiscovery,
        Self::FinishService,
        Self::DocumentationTooling,
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
            Self::DocumentationTooling => "documentation-tooling",
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
            Self::DocumentationTooling => Some(SpecialCase::DocumentationEvidence),
            Self::InstrumentRunner | Self::EvidenceNormalization | Self::TestDiscovery => None,
        }
    }
}

/// The I18.31 special cases (W2), one per guarded surface.
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
    /// A documentation/audit-tooling change runs the
    /// `DocumentationEvidenceCheck` from a frozen outer script/generation and
    /// verifies the exact bytes it packages (I18.31:40).
    DocumentationEvidence,
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
            Self::DocumentationEvidence => "documentation-evidence",
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
            Self::DocumentationEvidence => SelfChangeSurface::DocumentationTooling,
        }
    }

    /// Verifies typed special-case evidence with this case's mechanic.
    ///
    /// Each arm calls the real check: the executor arm re-checks the
    /// outer-guardian digest half over the exact evidence bytes, the parser
    /// arm replays the bound corpus, the selection arm requires zero false
    /// negatives with lane coverage, the finish arm requires every
    /// forged and partial proof rejected, and the documentation arm re-hashes
    /// the frozen outer script and re-derives the exact packaged bytes.
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
            (Self::DocumentationEvidence, SpecialCaseEvidence::DocumentationEvidence(record)) => {
                verify_documentation_evidence(record)
            }
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
    /// Frozen outer `DocumentationEvidenceCheck` over the exact packaged bytes.
    ///
    /// Boxed because the record carries both byte sides of every packaged
    /// document and is much the largest of the five variants; `Box` is
    /// transparent to serde, so the wire shape is unchanged.
    DocumentationEvidence(Box<DocumentationEvidenceRecord>),
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
            Self::DocumentationEvidence(_) => SpecialCase::DocumentationEvidence,
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

/// The frozen outer pin a `DocumentationEvidenceCheck` is published under.
///
/// The values mirror `scripts/documentation_evidence_check.freeze.json`. A pin
/// is only evidence when the script it names re-hashes to the recorded digest:
/// "frozen" means the bytes are compared, never that a pin file is present.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrozenOuterPin {
    /// The outer generation the check is published under.
    pub generation: String,
    /// Repository-relative path of the outer script the pin freezes.
    pub script: String,
    /// The recorded digest of the frozen outer script bytes.
    pub script_sha256: EvidenceDigest,
}

/// The frozen outer script/generation one `DocumentationEvidenceCheck` really
/// executed from.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrozenOuterScript {
    /// The pin, as recorded.
    pub pin: FrozenOuterPin,
    /// The exact bytes of the outer script that executed the check.
    pub script_bytes: Vec<u8>,
}

impl FrozenOuterScript {
    /// Records the pin and the exact script bytes that really ran.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::InvalidText`] for a blank or control-bearing
    /// generation or script path.
    pub fn new(pin: FrozenOuterPin, script_bytes: Vec<u8>) -> Result<Self, SelfChangeError> {
        for (value, field) in [(&pin.generation, "generation"), (&pin.script, "script")] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(SelfChangeError::InvalidText { field });
            }
        }
        Ok(Self { pin, script_bytes })
    }
}

/// One document a frozen evidence package carries.
///
/// Both byte sides are carried deliberately: `packaged_bytes` are the bytes
/// the package re-extracted, and `source_bytes` are the bytes the candidate
/// generator claims it packaged from. Equality between them is the re-extraction
/// requirement of I18.31:56 — a post-package edit creates a new revision, so
/// any drift between the two is a refusal, not a warning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageDocument {
    /// Package-relative path, exactly as the manifest names it.
    pub path: String,
    /// The bytes the candidate generator packaged.
    pub source_bytes: Vec<u8>,
    /// The bytes the frozen package re-extracted for this path.
    pub packaged_bytes: Vec<u8>,
    /// The bytes the live workspace holds for this path, when the check was
    /// also run against a workspace.
    pub workspace_bytes: Option<Vec<u8>>,
}

impl PackageDocument {
    /// Records one packaged document. The path must be text.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::InvalidText`] for a blank or control-bearing
    /// path.
    pub fn new(
        path: impl Into<String>,
        source_bytes: Vec<u8>,
        packaged_bytes: Vec<u8>,
        workspace_bytes: Option<Vec<u8>>,
    ) -> Result<Self, SelfChangeError> {
        let path = path.into();
        if path.trim().is_empty() || path.chars().any(char::is_control) {
            return Err(SelfChangeError::InvalidText { field: "path" });
        }
        Ok(Self {
            path,
            source_bytes,
            packaged_bytes,
            workspace_bytes,
        })
    }
}

/// The versioned copy a manifest intentionally publishes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VersionedCopy {
    /// Package-relative path the manifest points the versioned copy at.
    pub path: String,
    /// The digest the manifest records for that path.
    pub sha256: EvidenceDigest,
}

/// The machine manifest recorded inside a frozen evidence package.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Every path the manifest names, with the digest recorded for it.
    pub files: BTreeMap<String, EvidenceDigest>,
    /// The file count the manifest generated from its source revision.
    pub file_count: u64,
    /// Local evidence the package references, resolved by digest.
    pub evidence_refs: Vec<String>,
    /// The versioned copy the manifest publishes, when one is published.
    pub versioned_copy: Option<VersionedCopy>,
}

/// The machine ledger recorded inside a frozen evidence package.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageLedger {
    /// Package-relative path of the Markdown document the ledger covers.
    pub markdown: String,
    /// The digest the ledger records for that document.
    pub markdown_sha256: EvidenceDigest,
}

/// The stable reason-code dispositions recorded inside a frozen package.
///
/// A disposition outside [`STABLE_AGENT_RESPONSE_DISPOSITIONS`] fails to
/// round-trip: an unknown additive reason code cannot be decoded back into a
/// stable `AgentResponseDisposition`, so it may not appear in a frozen package.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageDispositions {
    /// Reason code to recorded disposition.
    pub codes: BTreeMap<String, String>,
}

/// The I18.31:40 `DocumentationEvidenceCheck` evidence admitted for one
/// documentation/audit-tooling change.
///
/// # A candidate documentation generator cannot certify itself
///
/// There is no verdict field, no `accepted` boolean, and no report string on
/// this record. The only outcome is the absence of a recomputed refusal:
/// every rule below recomputes a digest, a byte comparison, or a text scan
/// from the bytes carried here, and a caller that merely asserts the package
/// is green can satisfy none of them. I18.31:56 — "The candidate
/// documentation generator cannot certify itself solely by emitting a green
/// report" — is therefore structural rather than documentary: there is no
/// place in the type where a self-reported pass can be written.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DocumentationEvidenceRecord {
    /// The frozen outer script/generation the check really ran from.
    pub script: FrozenOuterScript,
    /// Every document the package carries, with both byte sides.
    pub documents: Vec<PackageDocument>,
    /// The machine manifest recorded in the package.
    pub manifest: PackageManifest,
    /// The machine ledger recorded in the package, when it carries one.
    pub ledger: Option<PackageLedger>,
    /// The stable reason-code dispositions recorded in the package.
    pub dispositions: Option<PackageDispositions>,
}

impl DocumentationEvidenceRecord {
    /// Records one frozen documentation-evidence run.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::DocumentationPackageEmpty`] when the package
    /// carries no document, [`SelfChangeError::InvalidText`] for a blank or
    /// control-bearing path, or
    /// [`SelfChangeError::DocumentationDuplicateDocument`] when two documents
    /// share one path. The non-empty requirement is what stops an empty
    /// package from passing every rule vacuously.
    pub fn new(
        script: FrozenOuterScript,
        documents: Vec<PackageDocument>,
        manifest: PackageManifest,
        ledger: Option<PackageLedger>,
        dispositions: Option<PackageDispositions>,
    ) -> Result<Self, SelfChangeError> {
        if documents.is_empty() {
            return Err(SelfChangeError::DocumentationPackageEmpty);
        }
        let mut seen = BTreeSet::new();
        for document in &documents {
            if document.path.trim().is_empty() || document.path.chars().any(char::is_control) {
                return Err(SelfChangeError::InvalidText { field: "path" });
            }
            if !seen.insert(document.path.as_str()) {
                return Err(SelfChangeError::DocumentationDuplicateDocument {
                    path: document.path.clone(),
                });
            }
        }
        Ok(Self {
            script,
            documents,
            manifest,
            ledger,
            dispositions,
        })
    }

    /// The re-extracted document the manifest names at `path`.
    #[must_use]
    pub fn document(&self, path: &str) -> Option<&PackageDocument> {
        self.documents.iter().find(|document| document.path == path)
    }

    /// The packaged document bytes, re-hashed here over the exact re-extracted
    /// bytes rather than trusted from the manifest.
    fn packaged_digest(&self, path: &str) -> Option<EvidenceDigest> {
        self.document(path)
            .and_then(|document| EvidenceDigest::new(sha256_hex(&document.packaged_bytes)).ok())
    }
}

/// Fields `ReceiptEnvelope` owns, which a receipt payload may never redefine.
///
/// Mirrors the frozen outer script's own list, read from
/// `scripts/documentation_evidence_check.py`; the ownership rule is I18.31's
/// and I0.14's, not this module's invention.
pub const ENVELOPE_OWNED_RECEIPT_FIELDS: [&str; 4] =
    ["identity", "authority", "fence", "provenance"];

/// The stable `AgentResponseDisposition` values an additive reason code
/// round-trips under.
///
/// Mirrors the frozen outer script's own list, read from
/// `scripts/documentation_evidence_check.py`.
pub const STABLE_AGENT_RESPONSE_DISPOSITIONS: [&str; 4] = ["accept", "reject", "defer", "escalate"];

/// Verifies one `DocumentationEvidenceCheck` executed from a frozen outer
/// script/generation over the exact bytes it packages (I18.31:40, I18.31:56).
///
/// Each arm recomputes its verdict from the carried bytes; none of them can be
/// satisfied by asserting a result:
///
/// - `verify_frozen_outer_script` re-hashes the exact outer script bytes with
///   [`sha256_hex`] and requires the recorded pin digest, and requires the
///   script's own bytes to declare the recorded generation.
/// - `verify_package_reextraction` requires every manifest entry and every
///   evidence reference to resolve in the re-extracted package, recomputes
///   each packaged document's digest and requires the recorded one, and
///   refuses any byte drift between the source bytes and the re-extracted
///   bytes.
/// - `verify_versioned_copy` requires the manifest's versioned copy to resolve
///   and to re-hash to the digest the manifest records for it.
/// - `verify_ledger` recomputes the ledger's Markdown digest from the packaged
///   bytes and requires the recorded one.
/// - `verify_workspace_divergence` requires the workspace bytes to equal the
///   re-extracted package bytes.
/// - `verify_generated_counts` recomputes the manifest's file count from the
///   documents that resolve.
/// - `verify_text_corpus` scans the packaged text for the remaining negative
///   corpus classes: unresolved template sentinels, a `CURRENT_VERIFIED` claim
///   with no resolving evidence reference, two contract sections defining the
///   same name with different body digests, a receipt payload redefining an
///   [`ENVELOPE_OWNED_RECEIPT_FIELDS`] field, and a reason code that does not
///   round-trip under a [`STABLE_AGENT_RESPONSE_DISPOSITIONS`] disposition.
///
/// # Errors
///
/// Returns the first recomputed refusal. Every corruption class in the I18.31
/// negative corpus has its own typed variant; none of them is a generic error.
pub fn verify_documentation_evidence(
    record: &DocumentationEvidenceRecord,
) -> Result<(), SelfChangeError> {
    verify_frozen_outer_script(&record.script)?;
    verify_package_reextraction(record)?;
    verify_versioned_copy(record)?;
    verify_ledger(record)?;
    verify_workspace_divergence(record)?;
    verify_generated_counts(record)?;
    verify_text_corpus(record)
}

/// Re-hashes the exact outer script bytes and requires the recorded pin.
fn verify_frozen_outer_script(script: &FrozenOuterScript) -> Result<(), SelfChangeError> {
    if sha256_hex(&script.script_bytes) != script.pin.script_sha256.as_str() {
        return Err(SelfChangeError::DocumentationFrozenScriptDrift {
            generation: script.pin.generation.clone(),
        });
    }
    if !String::from_utf8_lossy(&script.script_bytes).contains(&script.pin.generation) {
        return Err(SelfChangeError::DocumentationGenerationMismatch {
            generation: script.pin.generation.clone(),
        });
    }
    Ok(())
}

/// Requires the package to re-extract to the bytes it was built from.
fn verify_package_reextraction(
    record: &DocumentationEvidenceRecord,
) -> Result<(), SelfChangeError> {
    for document in &record.documents {
        if document.source_bytes != document.packaged_bytes {
            return Err(SelfChangeError::DocumentationPostPackageMutation {
                path: document.path.clone(),
            });
        }
    }
    for (path, expected) in &record.manifest.files {
        let Some(observed) = record.packaged_digest(path) else {
            return Err(SelfChangeError::DocumentationMissingReferencedArtifact {
                path: path.clone(),
            });
        };
        if observed.as_str() != expected.as_str() {
            return Err(SelfChangeError::DocumentationPackageDigestMismatch { path: path.clone() });
        }
    }
    for reference in &record.manifest.evidence_refs {
        if record.document(reference).is_none() {
            return Err(SelfChangeError::DocumentationMissingReferencedArtifact {
                path: reference.clone(),
            });
        }
    }
    Ok(())
}

/// Requires the manifest's versioned copy to resolve to the bytes it names.
fn verify_versioned_copy(record: &DocumentationEvidenceRecord) -> Result<(), SelfChangeError> {
    let Some(versioned) = &record.manifest.versioned_copy else {
        return Ok(());
    };
    match record.packaged_digest(&versioned.path) {
        Some(observed) if observed == versioned.sha256 => Ok(()),
        _ => Err(SelfChangeError::DocumentationVersionedCopyMismatch {
            path: versioned.path.clone(),
        }),
    }
}

/// Recomputes the ledger's Markdown digest from the packaged bytes.
fn verify_ledger(record: &DocumentationEvidenceRecord) -> Result<(), SelfChangeError> {
    let Some(ledger) = &record.ledger else {
        return Ok(());
    };
    match record.packaged_digest(&ledger.markdown) {
        Some(observed) if observed == ledger.markdown_sha256 => Ok(()),
        _ => Err(SelfChangeError::DocumentationLedgerStale {
            path: ledger.markdown.clone(),
        }),
    }
}

/// Requires every workspace side to equal the re-extracted package bytes.
fn verify_workspace_divergence(
    record: &DocumentationEvidenceRecord,
) -> Result<(), SelfChangeError> {
    for document in &record.documents {
        if let Some(workspace) = &document.workspace_bytes
            && workspace != &document.packaged_bytes
        {
            return Err(SelfChangeError::DocumentationWorkspaceDivergence {
                path: document.path.clone(),
            });
        }
    }
    Ok(())
}

/// Recomputes the manifest's generated file count from the resolved documents.
fn verify_generated_counts(record: &DocumentationEvidenceRecord) -> Result<(), SelfChangeError> {
    let observed = record
        .manifest
        .files
        .keys()
        .filter(|path| record.document(path).is_some())
        .count();
    let observed = u64::try_from(observed).unwrap_or(u64::MAX);
    if observed != record.manifest.file_count {
        return Err(SelfChangeError::DocumentationCountFromDifferentRevision {
            expected: record.manifest.file_count,
            observed,
        });
    }
    Ok(())
}

/// Scans the packaged text for the remaining negative corpus classes.
fn verify_text_corpus(record: &DocumentationEvidenceRecord) -> Result<(), SelfChangeError> {
    let texts: Vec<(&str, &str)> = record
        .documents
        .iter()
        .filter_map(|document| {
            std::str::from_utf8(&document.packaged_bytes)
                .ok()
                .map(|text| (document.path.as_str(), text))
        })
        .collect();
    let has_evidence = record
        .manifest
        .evidence_refs
        .iter()
        .any(|reference| record.document(reference).is_some());
    for (path, text) in &texts {
        if let Some(sentinel) = template_sentinels(text).into_iter().next() {
            return Err(SelfChangeError::DocumentationUnresolvedTemplate {
                path: (*path).to_owned(),
                sentinel,
            });
        }
        if text.contains("CURRENT_VERIFIED") && !has_evidence {
            return Err(
                SelfChangeError::DocumentationCurrentVerifiedWithoutEvidence {
                    path: (*path).to_owned(),
                },
            );
        }
        if let Some(field) = redefined_envelope_field(path, text) {
            return Err(SelfChangeError::DocumentationReceiptFieldRedefinition {
                path: (*path).to_owned(),
                field,
            });
        }
    }
    verify_contract_sections(&texts)?;
    verify_dispositions(record)
}

/// Requires every `## Contract:` section of one name to share one body digest.
fn verify_contract_sections(texts: &[(&str, &str)]) -> Result<(), SelfChangeError> {
    let mut seen: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (path, text) in texts {
        for (name, digest) in contract_section_digests(text) {
            let diverges = seen
                .get(&name)
                .is_some_and(|(_, first)| first.as_str() != digest.as_str());
            if diverges {
                return Err(SelfChangeError::DocumentationContractSectionDivergence { name });
            }
            seen.entry(name)
                .or_insert_with(|| ((*path).to_owned(), digest));
        }
    }
    Ok(())
}

/// Requires every recorded reason code to round-trip under a stable
/// `AgentResponseDisposition`.
fn verify_dispositions(record: &DocumentationEvidenceRecord) -> Result<(), SelfChangeError> {
    let Some(dispositions) = &record.dispositions else {
        return Ok(());
    };
    for (code, disposition) in &dispositions.codes {
        if !STABLE_AGENT_RESPONSE_DISPOSITIONS.contains(&disposition.as_str()) {
            return Err(SelfChangeError::DocumentationUnknownDisposition {
                code: code.clone(),
                disposition: disposition.clone(),
            });
        }
    }
    Ok(())
}

/// The `{{NAME}}` template sentinels one rendered document still carries.
fn template_sentinels(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = BTreeSet::new();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'{' && bytes[index + 1] == b'{' {
            let mut end = index + 2;
            if end < bytes.len() && bytes[end].is_ascii_uppercase() {
                while end < bytes.len()
                    && (bytes[end].is_ascii_uppercase()
                        || bytes[end].is_ascii_digit()
                        || bytes[end] == b'_')
                {
                    end += 1;
                }
                if end + 1 < bytes.len() && bytes[end] == b'}' && bytes[end + 1] == b'}' {
                    found.insert(text[index..end + 2].to_owned());
                    index = end + 2;
                    continue;
                }
            }
        }
        index += 1;
    }
    found.into_iter().collect()
}

/// The `## Contract: NAME` sections of one document, with the digest of each
/// section body.
fn contract_section_digests(text: &str) -> BTreeMap<String, String> {
    const PREFIX: &str = "## Contract:";
    let mut sections: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if let Some(name) = line.trim_start().strip_prefix(PREFIX) {
            let name = name.trim().to_owned();
            if name.is_empty() {
                current = None;
            } else {
                sections.entry(name.clone()).or_default();
                current = Some(name);
            }
        } else if let Some(name) = &current {
            sections
                .entry(name.clone())
                .or_default()
                .push(line.to_owned());
        }
    }
    sections
        .into_iter()
        .map(|(name, body)| {
            let digest = sha256_hex(body.join("\n").as_bytes());
            (name, digest)
        })
        .collect()
}

/// The [`ENVELOPE_OWNED_RECEIPT_FIELDS`] field one receipt payload redefines.
///
/// Only receipt payloads are read: a package stores them under `receipts/`
/// with a `.json` suffix, which is the layout the frozen outer script itself
/// documents. A non-JSON or unparsable receipt is not a redefinition and
/// returns `None`.
fn redefined_envelope_field(path: &str, text: &str) -> Option<String> {
    let is_receipt = path.starts_with("receipts/")
        && std::path::Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
    if !is_receipt {
        return None;
    }
    let payload: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = payload.as_object()?;
    ENVELOPE_OWNED_RECEIPT_FIELDS
        .iter()
        .find(|owned| object.contains_key(**owned))
        .map(|owned| (**owned).to_owned())
}

/// The five I18.31 bootstrap phases in cutover order, plus the terminal
/// oracle-conflict state.
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
    /// Terminal state: an oracle conflict was raised and resolved under
    /// the oracle rule (W3). The machine accepts no further evidence.
    OracleConflict,
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
///
/// The two program identities are the independence evidence of this record.
/// `last_known_good_program` and `candidate_program` are the machine-computed
/// content digests of the two executables the two passes really ran, observed
/// by the driver from the file bytes — not a bundle-supplied path, name, or
/// string. I18.31 requires cutover to occur only on independent evidence, and
/// "a changed verifier cannot be the sole authority proving its own
/// correctness" is exactly the case a comparison of one implementation with
/// itself fails to catch: every axis matches because there is only one side.
/// Carrying the two observed program identities on the record makes that
/// independence an observed, compared fact of the comparison itself, so
/// [`SelfChangeBootstrap::record_comparison`] can refuse a candidate that is
/// not a distinct program before any receipt can be minted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShadowComparisonRecord {
    /// The changed surface under comparison (W5 scope).
    pub surface: SelfChangeSurface,
    /// Old generation producing the reference side.
    pub old_generation: u64,
    /// Candidate generation producing the shadow side.
    pub candidate_generation: u64,
    /// Machine-observed program identity the last-known-good pass really ran.
    pub last_known_good_program: EvidenceDigest,
    /// Machine-observed program identity the candidate shadow pass really ran.
    pub candidate_program: EvidenceDigest,
    /// Per-axis verdicts.
    pub verdicts: AxisVerdicts,
    /// Digest of the comparison evidence.
    pub evidence: EvidenceDigest,
}

impl ShadowComparisonRecord {
    /// Records one comparison. Generations must advance, and the candidate
    /// program identity must be a machine-observed program distinct from the
    /// last-known-good one.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::NonAdvancingGeneration`] when the
    /// candidate does not advance past the old generation, or
    /// [`SelfChangeError::CandidateNotIndependent`] when both passes observed
    /// the same program.
    pub fn new(
        surface: SelfChangeSurface,
        old_generation: u64,
        candidate_generation: u64,
        last_known_good_program: EvidenceDigest,
        candidate_program: EvidenceDigest,
        verdicts: AxisVerdicts,
        evidence: EvidenceDigest,
    ) -> Result<Self, SelfChangeError> {
        if candidate_generation <= old_generation {
            return Err(SelfChangeError::NonAdvancingGeneration {
                old: old_generation,
                candidate: candidate_generation,
            });
        }
        if last_known_good_program == candidate_program {
            return Err(SelfChangeError::CandidateNotIndependent {
                program: candidate_program,
            });
        }
        Ok(Self {
            surface,
            old_generation,
            candidate_generation,
            last_known_good_program,
            candidate_program,
            verdicts,
            evidence,
        })
    }

    /// Whether every comparison axis matches.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.verdicts.is_clean()
    }

    /// Whether the two passes really observed distinct programs, which is the
    /// independent evidence I18.31 requires before a cutover.
    #[must_use]
    pub fn is_independent(&self) -> bool {
        self.last_known_good_program != self.candidate_program
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
///
/// Raised by the bootstrap machine itself on real rejection events:
/// [`SelfChangeBootstrap::cutover_or_reject`] on a refused cutover, and
/// [`SelfChangeBootstrap::record_comparison_or_escalate`] on a diverged
/// shadow comparison.
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

/// A refused bootstrap carried to its terminal oracle-rule outcome (W3).
///
/// The conflict binds the admitted surface and generation pair, so the
/// refusal it records cannot name a bootstrap it did not come from. The
/// resolution stays exhaustive — rejection by the old generation, or
/// escalation to a Human/independent route — and permanent
/// self-certification stays unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedOracleConflict {
    /// The raised conflict, bound to the refused bootstrap.
    pub conflict: OracleConflict,
    /// The terminal oracle-rule resolution.
    pub resolution: OracleResolution,
}

/// Outcome of [`SelfChangeBootstrap::record_comparison_or_escalate`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ComparisonOutcome {
    /// The comparison was clean; the machine advanced to canary.
    Advanced,
    /// The comparison diverged; the conflict was raised and escalated,
    /// and the machine is terminal.
    Escalated(ResolvedOracleConflict),
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
    /// The candidate shadow pass observed the same program as the
    /// last-known-good pass, so the comparison is not independent evidence
    /// (I18.31: "cutover occurs only after independent evidence"). A changed
    /// verifier can never be the sole authority proving its own correctness,
    /// and a candidate that runs the identical program image proves nothing a
    /// receipt could bind.
    #[error(
        "candidate observed program is not independent of the last-known-good program: {program:?}"
    )]
    CandidateNotIndependent {
        /// The machine-observed program identity both passes really ran.
        program: EvidenceDigest,
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
    /// A documentation evidence package carried no document, so every rule
    /// would pass vacuously.
    #[error("documentation evidence package carries no document")]
    DocumentationPackageEmpty,
    /// Two packaged documents share one path.
    #[error("documentation evidence package carries path {path} twice")]
    DocumentationDuplicateDocument {
        /// The duplicated package-relative path.
        path: String,
    },
    /// The exact outer script bytes do not re-hash to the recorded frozen
    /// pin digest: the script is not frozen at the recorded generation.
    #[error("frozen outer script bytes do not re-hash to the pinned generation {generation}")]
    DocumentationFrozenScriptDrift {
        /// The recorded generation.
        generation: String,
    },
    /// The outer script's own bytes do not declare the recorded generation, so
    /// a record naming a different generation is refused.
    #[error("frozen outer script does not declare the recorded generation {generation}")]
    DocumentationGenerationMismatch {
        /// The recorded generation.
        generation: String,
    },
    /// A packaged document's source bytes differ from the bytes the package
    /// re-extracted: a post-package edit is a new revision (I18.31:56).
    #[error("packaged document {path} differs from the bytes it was built from")]
    DocumentationPostPackageMutation {
        /// The mutated package-relative path.
        path: String,
    },
    /// The recomputed packaged digest differs from the recorded manifest
    /// digest.
    #[error("packaged document {path} does not re-hash to its recorded manifest digest")]
    DocumentationPackageDigestMismatch {
        /// The diverging package-relative path.
        path: String,
    },
    /// A manifested artifact or an evidence reference does not resolve in the
    /// re-extracted package.
    #[error("referenced artifact {path} does not resolve in the package")]
    DocumentationMissingReferencedArtifact {
        /// The unresolved package-relative path.
        path: String,
    },
    /// The manifest points at a versioned copy whose bytes are not the ones it
    /// records.
    #[error("manifest versioned copy {path} does not match the bytes it names")]
    DocumentationVersionedCopyMismatch {
        /// The mispointed package-relative path.
        path: String,
    },
    /// The ledger's recorded Markdown digest is stale against the packaged
    /// bytes.
    #[error("ledger for {path} is stale against the packaged bytes")]
    DocumentationLedgerStale {
        /// The ledger's package-relative path.
        path: String,
    },
    /// A packaged document's bytes differ from the live workspace file.
    #[error("packaged document {path} differs from the workspace file")]
    DocumentationWorkspaceDivergence {
        /// The diverging package-relative path.
        path: String,
    },
    /// The manifest's file count was generated from a different source
    /// revision than the one the package carries.
    #[error(
        "manifest file count {expected} was generated from a different revision ({observed} now)"
    )]
    DocumentationCountFromDifferentRevision {
        /// The recorded count.
        expected: u64,
        /// The recomputed count.
        observed: u64,
    },
    /// A published document still carries an unresolved template sentinel.
    #[error("packaged document {path} carries the unresolved template sentinel {sentinel}")]
    DocumentationUnresolvedTemplate {
        /// The offending package-relative path.
        path: String,
        /// The unresolved sentinel.
        sentinel: String,
    },
    /// A document claims `CURRENT_VERIFIED` with no executable evidence
    /// resolving.
    #[error("packaged document {path} claims CURRENT_VERIFIED with no executable evidence")]
    DocumentationCurrentVerifiedWithoutEvidence {
        /// The unevidenced package-relative path.
        path: String,
    },
    /// Two public contract sections define the same name with different body
    /// digests.
    #[error("contract section {name} is defined twice with different digests")]
    DocumentationContractSectionDivergence {
        /// The diverging contract section name.
        name: String,
    },
    /// A receipt payload redefines a field `ReceiptEnvelope` owns.
    #[error("receipt payload {path} redefines the envelope-owned field {field}")]
    DocumentationReceiptFieldRedefinition {
        /// The offending receipt path.
        path: String,
        /// The redefined field.
        field: String,
    },
    /// An unknown additive reason code does not round-trip under a stable
    /// `AgentResponseDisposition`.
    #[error("reason code {code} does not round-trip under a stable disposition ({disposition})")]
    DocumentationUnknownDisposition {
        /// The offending reason code.
        code: String,
        /// The recorded disposition.
        disposition: String,
    },
    /// The bootstrap raised an oracle conflict and is terminal.
    #[error("bootstrap raised an oracle conflict and accepts no further evidence")]
    OracleConflictTerminal,
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
/// Refusal is terminal under the oracle rule (W3): a refused cutover is
/// rejected via [`SelfChangeBootstrap::cutover_or_reject`], and a
/// diverged comparison escalates via
/// [`SelfChangeBootstrap::record_comparison_or_escalate`].
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
    conflict: Option<ResolvedOracleConflict>,
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
            conflict: None,
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

    /// The terminal oracle-conflict outcome, once the machine raises one.
    ///
    /// `None` while the bootstrap advances normally; `Some` after
    /// [`SelfChangeBootstrap::record_comparison_or_escalate`] escalates a
    /// diverged comparison. A rejected cutover consumes the machine, so
    /// its outcome travels on the [`ResolvedOracleConflict`] return.
    #[must_use]
    pub fn oracle_conflict(&self) -> Option<&ResolvedOracleConflict> {
        self.conflict.as_ref()
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

    /// Records the shadow comparison. It must be in scope, name the admitted
    /// generations, carry independent evidence, and match on every axis. Use
    /// [`SelfChangeBootstrap::record_comparison_or_escalate`] when a diverged
    /// comparison must escalate under the oracle rule instead of returning
    /// [`SelfChangeError::ComparisonDiverged`].
    ///
    /// The independence check runs here, in the owner that mints the receipt,
    /// rather than only in [`ShadowComparisonRecord::new`]: a record can also
    /// arrive through deserialization, and a record whose two passes observed
    /// the same program is refused here before the phase can advance.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::PhaseOrder`], [`SelfChangeError::SurfaceMismatch`],
    /// [`SelfChangeError::GenerationMismatch`], [`SelfChangeError::CandidateNotIndependent`],
    /// or [`SelfChangeError::ComparisonDiverged`].
    pub fn record_comparison(
        &mut self,
        record: ShadowComparisonRecord,
    ) -> Result<(), SelfChangeError> {
        self.require_phase(BootstrapPhase::Comparison)?;
        self.require_scope(record.surface)?;
        self.require_generations(record.old_generation, record.candidate_generation)?;
        if !record.is_independent() {
            return Err(SelfChangeError::CandidateNotIndependent {
                program: record.candidate_program.clone(),
            });
        }
        if !record.is_clean() {
            return Err(SelfChangeError::ComparisonDiverged {
                axes: record.verdicts.diverged_axes(),
            });
        }
        self.comparison = Some(record);
        self.phase = BootstrapPhase::Canary;
        Ok(())
    }

    /// Records the shadow comparison, escalating divergence (W3).
    ///
    /// A clean comparison advances to canary exactly like
    /// [`SelfChangeBootstrap::record_comparison`]. A diverged comparison
    /// is substantive oracle disagreement — neither generation can decide
    /// it unilaterally — so the machine raises the [`OracleConflict`]
    /// bound to this bootstrap, escalates it to `arbiter`, moves to the
    /// terminal [`BootstrapPhase::OracleConflict`], and stores the
    /// [`ResolvedOracleConflict`] for [`SelfChangeBootstrap::oracle_conflict`].
    ///
    /// A candidate that is not independent is not a disagreement between two
    /// generations, so it never escalates: there is no second generation whose
    /// view could resolve it. It surfaces as
    /// [`SelfChangeError::CandidateNotIndependent`] and leaves the machine
    /// untouched.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::PhaseOrder`], [`SelfChangeError::SurfaceMismatch`],
    /// [`SelfChangeError::GenerationMismatch`], or
    /// [`SelfChangeError::CandidateNotIndependent`] for driver-side misuse;
    /// the machine is untouched then. Divergence never errors: it
    /// escalates.
    pub fn record_comparison_or_escalate(
        &mut self,
        record: ShadowComparisonRecord,
        arbiter: ConflictArbiter,
    ) -> Result<ComparisonOutcome, SelfChangeError> {
        match self.record_comparison(record) {
            Ok(()) => Ok(ComparisonOutcome::Advanced),
            Err(SelfChangeError::ComparisonDiverged { axes }) => {
                let detail = format!("shadow comparison diverges on axes {axes:?}");
                let conflict = Self::bind_conflict(
                    self.surface,
                    self.old_generation,
                    self.candidate_generation,
                    &detail,
                );
                let resolution = conflict.escalate(arbiter);
                let outcome = ResolvedOracleConflict {
                    conflict,
                    resolution,
                };
                self.phase = BootstrapPhase::OracleConflict;
                self.conflict = Some(outcome.clone());
                Ok(ComparisonOutcome::Escalated(outcome))
            }
            Err(other) => Err(other),
        }
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
    /// phase opens; the case must guard the admitted surface. A machine
    /// terminal under the oracle rule accepts no further evidence.
    ///
    /// # Errors
    ///
    /// Returns [`SelfChangeError::PhaseOrder`], [`SelfChangeError::UnexpectedSpecialCase`],
    /// [`SelfChangeError::DuplicateSpecialCase`], or [`SelfChangeError::OracleConflictTerminal`].
    pub fn record_special_case(
        &mut self,
        case: SpecialCase,
        evidence: EvidenceDigest,
    ) -> Result<(), SelfChangeError> {
        if self.phase == BootstrapPhase::OracleConflict {
            return Err(SelfChangeError::OracleConflictTerminal);
        }
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
    /// Use [`SelfChangeBootstrap::cutover_or_reject`] when a refusal must
    /// reject the candidate under the oracle rule instead of returning
    /// the bare refusal.
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

    /// Cuts over, rejecting the candidate on any refusal (W3).
    ///
    /// Success mints the [`GenerationReceipt`] exactly like
    /// [`SelfChangeBootstrap::cutover`]. A refusal is a real
    /// candidate-rejection event: the machine raises the
    /// [`OracleConflict`] bound to this bootstrap and the old generation
    /// exercises its one unilateral power — [`OracleConflict::reject`] —
    /// so the returned [`ResolvedOracleConflict`] carries both the
    /// conflict and its terminal rejection.
    ///
    /// # Errors
    ///
    /// Returns the resolved conflict — never a bare refusal — when
    /// cutover refuses.
    pub fn cutover_or_reject(self) -> Result<GenerationReceipt, ResolvedOracleConflict> {
        let surface = self.surface;
        let old_generation = self.old_generation;
        let candidate_generation = self.candidate_generation;
        match self.cutover() {
            Ok(receipt) => Ok(receipt),
            Err(refusal) => {
                let reason = format!("cutover refused: {refusal}");
                let conflict =
                    Self::bind_conflict(surface, old_generation, candidate_generation, &reason);
                let resolution = conflict.reject(reason);
                Err(ResolvedOracleConflict {
                    conflict,
                    resolution,
                })
            }
        }
    }

    /// Binds an oracle conflict to one admitted bootstrap identity (W3).
    ///
    /// Generations advance by the [`SelfChangeBootstrap::admit`]
    /// invariant — the only constructor, with private fields — so the
    /// generation check always holds. The detail is machine-built; control
    /// characters are stripped and a blank result falls back to the
    /// surface name, so the text check always holds too.
    fn bind_conflict(
        surface: SelfChangeSurface,
        old_generation: u64,
        candidate_generation: u64,
        detail: &str,
    ) -> OracleConflict {
        let clean: String = detail.chars().filter(|c| !c.is_control()).collect();
        let detail = if clean.trim().is_empty() {
            format!("oracle conflict on {name}", name = surface.as_str())
        } else {
            clean
        };
        OracleConflict {
            surface,
            old_generation,
            candidate_generation,
            detail,
        }
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
