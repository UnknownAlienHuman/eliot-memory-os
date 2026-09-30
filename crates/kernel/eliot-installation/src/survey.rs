//! Ordered, metadata-only installation survey coordinator.
//!
//! `I3.3` fixes the probe order — known configuration paths and manifests,
//! then PATH metadata, then file version/signature, and only then a safe
//! `--version` or initialization probe — and states that a discovered
//! executable is not started automatically as a trusted Module. This module
//! owns that order and nothing else: it walks the four stages in the mandatory
//! sequence, retains each stage's result, evidence, denied, unreadable and
//! ambiguous inputs together with its coverage, and coalesces alias
//! observations by the exact identity the observation source reports.
//!
//! The coordinator performs no process execution, no filesystem write and no
//! environment mutation, and there is deliberately no port here that could.
//! `--version` is not inherently safe and the bounded `ProcessExecutor` that
//! would own it belongs to a different cell, so `AdmittedSafeProbe` records a
//! typed outcome and runs nothing: a non-empty catalogue `safe_probes` list is
//! a detection recipe, never permission to execute the discovered program.
//!
//! `I3.3.1` keeps this a detection-only surface. Nothing here asserts that
//! anything is installed, healthy, supported or admitted, and the
//! `discovered`, `declared`, `probed`, `admitted`, `degraded` and `unsupported`
//! states belong to `I3.3.1` and `I3.4`, not to a survey observation. An
//! existing `SurrealDB` process or installation stays an observation or import
//! candidate: this module records no adopt, reuse, kill or port decision, and
//! `I3.15` keeps the `InstallationTransaction` the single installation owner.
//!
//! The one of those states a survey *does* carry is `unsupported`: a catalogue
//! entry whose `supported_platforms` excludes the surveyed platform is reported
//! in [`InstallationSurvey::unsupported_families`] and is never walked. A family
//! the accepted revision excludes here therefore cannot appear as a detection
//! result that merely found nothing, which is what makes "all seed families are
//! accounted for as supported detection or an explicit gap" true of the report
//! rather than only of the catalogue.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    InstallationError, IntegrationCategory, IntegrationDiscoveryCatalogue,
    IntegrationDiscoveryCatalogueEntry, PlatformHandle, handle,
};

/// The four mandatory survey stages, in their fixed probe order.
///
/// The discriminants are the order, [`Self::ORDER`] is the order, and every
/// traversal and [`InstallationSurvey::validate`] uses that one slice, so a
/// stage can never be visited out of sequence or visited twice.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SurveyStage {
    /// Known configuration paths and manifests.
    KnownConfigOrManifest = 0,
    /// PATH metadata.
    PathMetadata = 1,
    /// Exact file version, signature and identity.
    FileVersionSignatureIdentity = 2,
    /// A safe version or initialization probe, only after the identity stage.
    AdmittedSafeProbe = 3,
}

impl SurveyStage {
    /// The mandatory stage order, walked exactly once per family.
    pub const ORDER: [Self; 4] = [
        Self::KnownConfigOrManifest,
        Self::PathMetadata,
        Self::FileVersionSignatureIdentity,
        Self::AdmittedSafeProbe,
    ];

    /// Whether this stage may resolve an exact observed identity.
    ///
    /// Only the file version, signature and identity stage may. A hit in PATH
    /// is an observation about a name; promoting it into an identity, an
    /// admission or a capability is exactly what `I3.3` prohibits.
    pub const fn resolves_identity(self) -> bool {
        matches!(self, Self::FileVersionSignatureIdentity)
    }
}

/// The closed set of coverage states one survey stage can yield.
///
/// `Denied`, `Unreadable`, `Ambiguous` and `Withheld` are distinct from
/// `NotFound` on purpose: an observation that could not be obtained is never
/// reported as an absence. The states are never collapsed into a boolean, an
/// option or free text.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurveyStageOutcome {
    /// The stage inspected its inputs and observed at least one present.
    Found,
    /// The stage inspected its inputs and observed none present.
    NotFound,
    /// The input exists, but the observing identity was refused access to it.
    Denied,
    /// The input could not be read, so its content stays unknown.
    Unreadable,
    /// The input could not be attributed to exactly one identity.
    Ambiguous,
    /// The stage did not reach the input, so nothing was learned about it.
    Withheld,
}

/// Whether anything admits a safe probe for one exact observed identity.
///
/// This is deliberately not derivable from the catalogue. `I3.3.1` makes the
/// catalogue a set of detection recipes, so a non-empty `safe_probes` list
/// leaves admission untouched; only an answer produced by an executor admitted
/// outside this coordinator admits anything here.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurveyProbeAdmission {
    /// Nothing admits a probe for this identity, so none was attempted.
    NotAdmitted,
    /// An executor admitted outside this coordinator already ran the probe and
    /// the survey retains its answer as evidence only.
    AnsweredByAdmittedExecutor,
}

/// One metadata observation about one input at one stage.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyInputObservation {
    /// The inspected input: a known location, a PATH entry or an identity
    /// target.
    pub input: PlatformHandle,
    /// What inspecting this input yielded.
    pub outcome: SurveyStageOutcome,
    /// Exact observed identity, reported by the file identity stage only.
    pub observed_identity: Option<PlatformHandle>,
    /// Bounded, non-secret evidence handle retained for this observation.
    pub evidence: Option<PlatformHandle>,
}

impl SurveyInputObservation {
    /// Validates the observation and the stage/identity rule.
    ///
    /// An identity outside the file identity stage is rejected rather than
    /// reinterpreted, so a PATH or manifest hit can never be promoted into an
    /// identity by a lenient reader.
    pub fn validate(&self, stage: SurveyStage) -> Result<(), InstallationError> {
        handle(&self.input, "survey.observation.input")?;
        if let Some(observed_identity) = &self.observed_identity {
            handle(observed_identity, "survey.observation.observed_identity")?;
            if !stage.resolves_identity() {
                return Err(InstallationError::InvalidField {
                    field: "survey.observation.observed_identity".to_owned(),
                    reason: "only the file version, signature and identity stage may resolve an \
                             identity; a known-location or PATH hit is an observation"
                        .to_owned(),
                });
            }
            if self.outcome != SurveyStageOutcome::Found {
                return Err(InstallationError::InvalidField {
                    field: "survey.observation.outcome".to_owned(),
                    reason: "an observed identity requires the Found outcome".to_owned(),
                });
            }
        }
        if let Some(evidence) = &self.evidence {
            handle(evidence, "survey.observation.evidence")?;
        }
        Ok(())
    }
}

/// One stage's retained result: its outcome, its evidence, and its coverage.
///
/// The buckets partition what the stage was asked about, so an unavailable
/// observation is always visible as itself and never as an absence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyStageResult {
    /// The stage this result belongs to.
    pub stage: SurveyStage,
    /// The stage's single coverage outcome over every input it was asked about.
    pub outcome: SurveyStageOutcome,
    /// Distinct inputs the stage was asked about, ascending.
    pub inputs: Vec<PlatformHandle>,
    /// Inputs observed present, ascending.
    pub found: Vec<PlatformHandle>,
    /// Inputs observed absent, ascending.
    pub not_found: Vec<PlatformHandle>,
    /// Inputs the observing identity was refused, ascending.
    pub denied: Vec<PlatformHandle>,
    /// Inputs that could not be read, ascending.
    pub unreadable: Vec<PlatformHandle>,
    /// Inputs that could not be attributed to one identity, ascending.
    pub ambiguous: Vec<PlatformHandle>,
    /// Inputs the stage itself declined to reach, ascending.
    pub withheld: Vec<PlatformHandle>,
    /// Catalogue inputs the stage never inspected, ascending.
    pub not_covered: Vec<PlatformHandle>,
    /// Bounded, non-secret evidence handles retained, ascending and distinct.
    pub evidence: Vec<PlatformHandle>,
}

/// One distinct installation, keyed only by its exact observed identity.
///
/// Two observations that resolve to the same identity coalesce here and keep
/// every input that produced it in [`Self::aliases`]. Two observations that
/// merely share a display name or a directory but report different identities
/// stay separate candidates, because the identity is the only key.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyCandidate {
    /// The exact observed identity reported by the identity stage.
    pub observed_identity: PlatformHandle,
    /// Every input that resolved to this exact identity, ascending.
    pub aliases: Vec<PlatformHandle>,
    /// Whether anything admits a safe probe for this identity.
    pub probe_admission: SurveyProbeAdmission,
    /// The probe stage's coverage outcome for this exact identity.
    pub probe_outcome: SurveyStageOutcome,
    /// The answer an admitted executor reported, ascending. Evidence only: it
    /// is empty whenever [`Self::probe_admission`] is `NotAdmitted`.
    pub probe_answers: Vec<PlatformHandle>,
}

/// One catalogue family's complete ordered survey result.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyFamilyReport {
    /// The catalogue family this report belongs to.
    pub family_id: PlatformHandle,
    /// The discovery category carried by the validated catalogue entry.
    pub category: IntegrationCategory,
    /// One result per stage, in [`SurveyStage::ORDER`].
    ///
    /// These results describe the family's whole input coverage, including
    /// inputs that never resolved to a single identity. Per-identity probe
    /// lineage lives on [`Self::candidates`].
    pub stages: Vec<SurveyStageResult>,
    /// Distinct installations observed for this family, ascending by identity.
    pub candidates: Vec<SurveyCandidate>,
}

/// One catalogue family this survey explicitly reports as unsupported.
///
/// `I3.3.1` declares `supported_platforms` per entry and requires `unsupported`
/// to be shown separately from a detection result. A recipe the accepted
/// revision does not declare valid on the platform being surveyed therefore
/// belongs here and is never walked: it has no stage result, no candidate and
/// no evidence, because this survey says nothing about it in either direction.
/// Reporting the gap is the point — an unsupported family must never be
/// indistinguishable from a family that was surveyed and found nothing.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyUnsupportedFamily {
    /// The catalogue family this gap is about.
    pub family_id: PlatformHandle,
    /// Discovery category carried by the validated catalogue entry.
    pub category: IntegrationCategory,
}

/// A probe answer already produced by an executor admitted outside this
/// coordinator.
///
/// The survey retains the answer as evidence and re-derives nothing: an answer
/// is not an admission, and this coordinator never runs a process to obtain
/// one.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurveyProbeAnswer {
    /// Catalogue family the answered identity was observed under.
    pub family_id: PlatformHandle,
    /// Exact observed identity that was probed.
    pub observed_identity: PlatformHandle,
    /// Bounded, non-secret answer handle reported by the executor.
    pub answer: PlatformHandle,
}

/// A metadata-only source of installation survey observations.
///
/// Implementations read existing platform metadata. They do not execute a
/// discovered program, mutate the environment or write to the filesystem:
/// finding a name in PATH is not permission to run it.
///
/// The three methods are the first three stages of [`SurveyStage::ORDER`].
/// There is deliberately no method for `AdmittedSafeProbe`, because this
/// coordinator has no execution port to call.
pub trait SurveyObservationSource {
    /// Inspects known configuration paths and manifests.
    ///
    /// The inspected inputs are the entry's `known_locations`, so an input
    /// this method does not report becomes a coverage hole rather than an
    /// absence.
    fn observe_known_config_or_manifest(
        &self,
        entry: &IntegrationDiscoveryCatalogueEntry,
    ) -> Result<Vec<SurveyInputObservation>, InstallationError>;

    /// Inspects PATH metadata.
    ///
    /// This stage may not report an observed identity; doing so is a
    /// [`InstallationError::InvalidField`], not an identity.
    fn observe_path_metadata(
        &self,
        entry: &IntegrationDiscoveryCatalogueEntry,
    ) -> Result<Vec<SurveyInputObservation>, InstallationError>;

    /// Inspects the exact file version, signature and identity.
    ///
    /// This is the only stage that resolves an identity, and it always runs
    /// before the probe stage.
    fn observe_file_identity(
        &self,
        entry: &IntegrationDiscoveryCatalogueEntry,
    ) -> Result<Vec<SurveyInputObservation>, InstallationError>;
}

/// One complete, deterministic, metadata-only survey of a discovery catalogue.
///
/// A survey report is a detection-only observation record. It asserts nothing
/// about installation, health, support or capability admission, and it is not
/// itself evidence in the `I3.4` sense: it carries observations for the
/// Governor-owned capability registry to weigh.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationSurvey {
    /// Catalogue origin this report was produced from.
    pub catalogue_origin: PlatformHandle,
    /// Catalogue revision this report was produced from.
    pub catalogue_revision: u64,
    /// One report per catalogue entry, ascending by family identity.
    pub families: Vec<SurveyFamilyReport>,
    /// Catalogue entries whose recipe does not declare the surveyed platform,
    /// ascending by family identity.
    ///
    /// Every catalogue entry appears in exactly one of [`Self::families`] and
    /// this list, so a family that was not surveyed is reported as an explicit
    /// gap instead of quietly disappearing from the report. This partition is an
    /// internal consistency invariant of one survey; it is not the completeness
    /// check. Completeness is owned by
    /// [`IntegrationDiscoveryCatalogue::require_seed_family_coverage`](super::IntegrationDiscoveryCatalogue::require_seed_family_coverage),
    /// which is checked against the independent `I3.3.1` seed set and never
    /// against either of these two lists.
    pub unsupported_families: Vec<SurveyUnsupportedFamily>,
}

impl InstallationSurvey {
    /// Validates stage order, coverage partitioning, alias ordering, the
    /// probe admission/answer correspondence and the surveyed/unsupported
    /// partition.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.catalogue_origin, "survey.catalogue_origin")?;
        if self.catalogue_revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "survey.catalogue_revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        let mut families = BTreeSet::new();
        for family in &self.families {
            handle(&family.family_id, "survey.families.family_id")?;
            if !families.insert(family.family_id.clone()) {
                return Err(InstallationError::Duplicate {
                    kind: "survey family".to_owned(),
                    identity: family.family_id.as_str().to_owned(),
                });
            }
            if family.stages.len() != SurveyStage::ORDER.len() {
                return Err(InstallationError::IncompleteObservation(
                    "survey family does not report every survey stage".to_owned(),
                ));
            }
            for (stage, result) in SurveyStage::ORDER.iter().zip(&family.stages) {
                if result.stage != *stage {
                    return Err(InstallationError::InvalidField {
                        field: "survey.families.stages".to_owned(),
                        reason: "must follow the mandatory survey stage order".to_owned(),
                    });
                }
                result.validate()?;
            }
            let mut identities = BTreeSet::new();
            for candidate in &family.candidates {
                handle(
                    &candidate.observed_identity,
                    "survey.candidates.observed_identity",
                )?;
                if !identities.insert(candidate.observed_identity.clone()) {
                    return Err(InstallationError::Duplicate {
                        kind: "survey candidate identity".to_owned(),
                        identity: candidate.observed_identity.as_str().to_owned(),
                    });
                }
                if candidate.aliases.is_empty() {
                    return Err(InstallationError::IncompleteObservation(
                        "survey candidate coalesced no alias input".to_owned(),
                    ));
                }
                validate_ascending("survey.candidates.aliases", &candidate.aliases)?;
                validate_ascending("survey.candidates.probe_answers", &candidate.probe_answers)?;
                let answered =
                    candidate.probe_admission == SurveyProbeAdmission::AnsweredByAdmittedExecutor;
                let answered_and_reported = candidate.probe_outcome == SurveyStageOutcome::Found;
                let carries_answer = !candidate.probe_answers.is_empty();
                if answered != answered_and_reported || answered != carries_answer {
                    return Err(InstallationError::IncompleteObservation(
                        "survey candidate probe admission, outcome and answers disagree".to_owned(),
                    ));
                }
            }
            validate_probe_stage_coverage(family)?;
        }
        // The surveyed and explicitly-unsupported sets partition the accepted
        // revision's entries. Overlap would let one family be reported both as
        // a detection result and as an explicit gap.
        let unsupported_ids = self
            .unsupported_families
            .iter()
            .map(|family| family.family_id.clone())
            .collect::<Vec<_>>();
        validate_ascending("survey.unsupported_families.family_id", &unsupported_ids)?;
        if unsupported_ids.iter().any(|id| families.contains(id)) {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Surveys `catalogue` against `source` on `observed_platform` and returns the
/// ordered report.
///
/// The catalogue is a set, so its entries are walked in ascending family order
/// and the source's per-stage observations are sorted before use: reordering
/// the catalogue or the observations cannot change the meaning of the result.
/// Stage order is mandatory, the probe stage runs nothing, aliases coalesce by
/// exact observed identity only, and every unavailable input keeps its own
/// coverage state.
///
/// `I3.3.1` declares `supported_platforms` per entry, so it is read here rather
/// than only shape-validated: an entry that does not declare `observed_platform`
/// is reported in
/// [`InstallationSurvey::unsupported_families`](InstallationSurvey::unsupported_families)
/// and is not walked, because a recipe the accepted revision excludes from this
/// platform cannot support a detection claim about it.
///
/// `catalogue` is validated before traversal and its [`InstallationError`]
/// surfaces unchanged; no second validation scheme applies here.
pub fn survey_installation(
    catalogue: &IntegrationDiscoveryCatalogue,
    observed_platform: &PlatformHandle,
    source: &dyn SurveyObservationSource,
    probe_answers: &[SurveyProbeAnswer],
) -> Result<InstallationSurvey, InstallationError> {
    catalogue.validate()?;
    let answers = index_probe_answers(probe_answers)?;

    // `validate()` already rejected duplicate family identities; this guard
    // only keeps the ordered map from silently dropping one if that ever
    // changes, and reports it through the same existing error variant.
    let mut ordered = BTreeMap::new();
    for entry in &catalogue.entries {
        if ordered.insert(entry.family_id.clone(), entry).is_some() {
            return Err(InstallationError::Duplicate {
                kind: "survey catalogue family".to_owned(),
                identity: entry.family_id.as_str().to_owned(),
            });
        }
    }

    let mut families = Vec::with_capacity(ordered.len());
    let mut unsupported_families = Vec::new();
    for (family_id, entry) in ordered {
        if !entry.supported_platforms.contains(observed_platform) {
            // Fail closed for the same reason the identity case below does: an
            // answer about a family this platform does not support says nothing
            // about this installation, so it is refused rather than parked.
            if answers.contains_key(&family_id) {
                return Err(InstallationError::IncompleteObservation(
                    "survey probe answer names a family unsupported on this platform".to_owned(),
                ));
            }
            unsupported_families.push(SurveyUnsupportedFamily {
                family_id,
                category: entry.category,
            });
            continue;
        }
        let empty = BTreeMap::new();
        let family_answers = answers.get(&family_id).unwrap_or(&empty);
        let report = survey_family(entry, source, family_answers)?;
        if report.family_id != family_id {
            return Err(InstallationError::IdentityConflict);
        }
        families.push(report);
    }

    let survey = InstallationSurvey {
        catalogue_origin: catalogue.origin.clone(),
        catalogue_revision: catalogue.revision,
        families,
        unsupported_families,
    };
    survey.validate()?;
    Ok(survey)
}

fn survey_family(
    entry: &IntegrationDiscoveryCatalogueEntry,
    source: &dyn SurveyObservationSource,
    family_answers: &BTreeMap<PlatformHandle, PlatformHandle>,
) -> Result<SurveyFamilyReport, InstallationError> {
    // Stage 1. The inspected inputs come from the catalogue, so an input the
    // source never reports is retained as not covered, never as absent.
    let known_observations = source.observe_known_config_or_manifest(entry)?;
    let known = stage_result(
        SurveyStage::KnownConfigOrManifest,
        &known_observations,
        &entry.known_locations,
    )?;

    // Stage 2. A PATH hit stays an observation about a name: this stage cannot
    // resolve an identity, and nothing here promotes it to one.
    let path_observations = source.observe_path_metadata(entry)?;
    let path = stage_result(SurveyStage::PathMetadata, &path_observations, &[])?;

    // Stage 3. The only stage that resolves an exact observed identity, and it
    // always runs before the probe stage.
    let identity_stage = SurveyStage::FileVersionSignatureIdentity;
    let identity_observations = source.observe_file_identity(entry)?;
    let identity = stage_result(identity_stage, &identity_observations, &[])?;

    let candidates = coalesce_candidates(&identity_observations, family_answers);

    // Fail closed: an answer bound to an identity this survey never observed
    // says nothing about this installation, so it is rejected rather than
    // attached to a candidate that does not exist.
    for answered_identity in family_answers.keys() {
        if !candidates
            .iter()
            .any(|candidate| &candidate.observed_identity == answered_identity)
        {
            return Err(InstallationError::IncompleteObservation(
                "survey probe answer names an identity the survey did not observe".to_owned(),
            ));
        }
    }

    let probe = probe_stage_result(&candidates);

    Ok(SurveyFamilyReport {
        family_id: entry.family_id.clone(),
        category: entry.category,
        stages: vec![known, path, identity, probe],
        candidates,
    })
}

fn stage_result(
    stage: SurveyStage,
    observations: &[SurveyInputObservation],
    expected: &[PlatformHandle],
) -> Result<SurveyStageResult, InstallationError> {
    let mut seen = BTreeSet::new();
    let mut found = BTreeSet::new();
    let mut not_found = BTreeSet::new();
    let mut denied = BTreeSet::new();
    let mut unreadable = BTreeSet::new();
    let mut ambiguous = BTreeSet::new();
    let mut withheld = BTreeSet::new();
    let mut evidence = BTreeSet::new();
    for observation in observations {
        observation.validate(stage)?;
        if !seen.insert(observation.input.clone()) {
            return Err(InstallationError::Duplicate {
                kind: format!("survey {stage:?} input"),
                identity: observation.input.as_str().to_owned(),
            });
        }
        let bucket = match observation.outcome {
            SurveyStageOutcome::Found => &mut found,
            SurveyStageOutcome::NotFound => &mut not_found,
            SurveyStageOutcome::Denied => &mut denied,
            SurveyStageOutcome::Unreadable => &mut unreadable,
            SurveyStageOutcome::Ambiguous => &mut ambiguous,
            SurveyStageOutcome::Withheld => &mut withheld,
        };
        bucket.insert(observation.input.clone());
        if let Some(retained) = &observation.evidence {
            evidence.insert(retained.clone());
        }
    }
    let not_covered = expected
        .iter()
        .filter(|input| !seen.contains(*input))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let mut result = SurveyStageResult {
        stage,
        outcome: SurveyStageOutcome::NotFound,
        inputs: seen.into_iter().collect(),
        found: found.into_iter().collect(),
        not_found: not_found.into_iter().collect(),
        denied: denied.into_iter().collect(),
        unreadable: unreadable.into_iter().collect(),
        ambiguous: ambiguous.into_iter().collect(),
        withheld: withheld.into_iter().collect(),
        not_covered,
        evidence: evidence.into_iter().collect(),
    };
    result.outcome = aggregate_outcome(&result);
    Ok(result)
}

/// Reduces one stage's coverage buckets to its single outcome.
///
/// The states are listed most obstructive first, so a denied, unreadable or
/// unattributable input is never hidden behind a sibling that happened to be
/// found, and an entirely unreported stage is an absence rather than a
/// collapsed uncertainty.
fn aggregate_outcome(result: &SurveyStageResult) -> SurveyStageOutcome {
    let states = [
        (!result.ambiguous.is_empty(), SurveyStageOutcome::Ambiguous),
        (!result.denied.is_empty(), SurveyStageOutcome::Denied),
        (
            !result.unreadable.is_empty(),
            SurveyStageOutcome::Unreadable,
        ),
        (
            !result.withheld.is_empty() || !result.not_covered.is_empty(),
            SurveyStageOutcome::Withheld,
        ),
        (!result.found.is_empty(), SurveyStageOutcome::Found),
        (!result.not_found.is_empty(), SurveyStageOutcome::NotFound),
    ];
    states
        .iter()
        .find(|(present, _)| *present)
        .map_or(SurveyStageOutcome::NotFound, |(_, outcome)| *outcome)
}

impl SurveyStageResult {
    /// Validates that the buckets partition the stage's inputs and that the
    /// recorded outcome is the one those buckets imply.
    pub fn validate(&self) -> Result<(), InstallationError> {
        for (field, values) in [
            ("survey.inputs", &self.inputs),
            ("survey.found", &self.found),
            ("survey.not_found", &self.not_found),
            ("survey.denied", &self.denied),
            ("survey.unreadable", &self.unreadable),
            ("survey.ambiguous", &self.ambiguous),
            ("survey.withheld", &self.withheld),
            ("survey.not_covered", &self.not_covered),
            ("survey.evidence", &self.evidence),
        ] {
            for value in values {
                handle(value, field)?;
            }
            validate_ascending(field, values)?;
        }
        let inputs = self.inputs.iter().collect::<BTreeSet<_>>();
        for bucket in [
            &self.found,
            &self.not_found,
            &self.denied,
            &self.unreadable,
            &self.ambiguous,
        ] {
            for value in bucket {
                if !inputs.contains(value) {
                    return Err(InstallationError::IncompleteObservation(
                        "survey stage bucket is not a subset of the stage inputs".to_owned(),
                    ));
                }
            }
        }
        for value in &self.withheld {
            if !inputs.contains(value) && !self.not_covered.contains(value) {
                return Err(InstallationError::IncompleteObservation(
                    "survey stage withheld an input it was not asked about".to_owned(),
                ));
            }
        }
        for value in &self.not_covered {
            if inputs.contains(value) {
                return Err(InstallationError::IncompleteObservation(
                    "survey stage covers and withholds the same input".to_owned(),
                ));
            }
        }
        // Every input the stage was asked about must land in exactly one
        // bucket, so an input that is only withheld is still accounted for and
        // a dropped input cannot be mistaken for an absence.
        let attributed = self.found.len()
            + self.not_found.len()
            + self.denied.len()
            + self.unreadable.len()
            + self.ambiguous.len()
            + self.withheld.len();
        if attributed != self.inputs.len() {
            return Err(InstallationError::IncompleteObservation(
                "survey stage buckets do not cover every input exactly once".to_owned(),
            ));
        }
        if self.outcome != aggregate_outcome(self) {
            return Err(InstallationError::IncompleteObservation(
                "survey stage outcome does not match its coverage buckets".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Coalesces identity-stage observations into one candidate per exact
/// observed identity.
///
/// Coalescing is by the reported identity alone: never by display name, never
/// by path prefix, never by apparent similarity. An input is an alias of an
/// identity only because the source reported that exact pairing, so two
/// observations sharing a name or a directory but reporting different
/// identities remain distinct installations.
fn coalesce_candidates(
    identity_observations: &[SurveyInputObservation],
    family_answers: &BTreeMap<PlatformHandle, PlatformHandle>,
) -> Vec<SurveyCandidate> {
    let mut aliases: BTreeMap<PlatformHandle, BTreeSet<PlatformHandle>> = BTreeMap::new();
    for observation in identity_observations {
        let Some(observed_identity) = &observation.observed_identity else {
            continue;
        };
        aliases
            .entry(observed_identity.clone())
            .or_default()
            .insert(observation.input.clone());
    }

    let mut candidates = Vec::with_capacity(aliases.len());
    for (observed_identity, inputs) in aliases {
        let answer = family_answers.get(&observed_identity).cloned();
        let (probe_admission, probe_outcome) = match answer {
            Some(_) => (
                SurveyProbeAdmission::AnsweredByAdmittedExecutor,
                SurveyStageOutcome::Found,
            ),
            None => (
                SurveyProbeAdmission::NotAdmitted,
                SurveyStageOutcome::Withheld,
            ),
        };
        candidates.push(SurveyCandidate {
            observed_identity,
            aliases: inputs.into_iter().collect(),
            probe_admission,
            probe_outcome,
            probe_answers: answer.into_iter().collect(),
        });
    }
    candidates
}

/// Builds the probe stage result without running anything.
///
/// The probe stage has no execution port here, so it only reflects answers an
/// executor admitted elsewhere already produced. An identity with no admitted
/// answer is `Withheld`, which is distinct from a probed and answered identity,
/// and an empty candidate set is `NotFound` because there was nothing to
/// probe.
fn probe_stage_result(candidates: &[SurveyCandidate]) -> SurveyStageResult {
    let mut found = BTreeSet::new();
    let mut withheld = BTreeSet::new();
    let mut evidence = BTreeSet::new();
    for candidate in candidates {
        match candidate.probe_admission {
            SurveyProbeAdmission::AnsweredByAdmittedExecutor => {
                found.insert(candidate.observed_identity.clone());
                evidence.extend(candidate.probe_answers.iter().cloned());
            }
            SurveyProbeAdmission::NotAdmitted => {
                withheld.insert(candidate.observed_identity.clone());
            }
        }
    }
    let mut result = SurveyStageResult {
        stage: SurveyStage::AdmittedSafeProbe,
        outcome: SurveyStageOutcome::NotFound,
        inputs: candidates
            .iter()
            .map(|candidate| candidate.observed_identity.clone())
            .collect(),
        found: found.into_iter().collect(),
        not_found: Vec::new(),
        denied: Vec::new(),
        unreadable: Vec::new(),
        ambiguous: Vec::new(),
        withheld: withheld.into_iter().collect(),
        not_covered: Vec::new(),
        evidence: evidence.into_iter().collect(),
    };
    result.outcome = aggregate_outcome(&result);
    result
}

/// Requires the family probe stage to describe exactly its candidates.
fn validate_probe_stage_coverage(family: &SurveyFamilyReport) -> Result<(), InstallationError> {
    let probe = family
        .stages
        .iter()
        .find(|result| result.stage == SurveyStage::AdmittedSafeProbe)
        .ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "survey family does not report the probe stage".to_owned(),
            )
        })?;
    let admitted = family
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.probe_admission == SurveyProbeAdmission::AnsweredByAdmittedExecutor
        })
        .count();
    if admitted != probe.found.len() {
        return Err(InstallationError::IncompleteObservation(
            "survey probe stage disagrees with its candidates about admitted identities".to_owned(),
        ));
    }
    Ok(())
}

fn index_probe_answers(
    probe_answers: &[SurveyProbeAnswer],
) -> Result<BTreeMap<PlatformHandle, BTreeMap<PlatformHandle, PlatformHandle>>, InstallationError> {
    let mut indexed: BTreeMap<PlatformHandle, BTreeMap<PlatformHandle, PlatformHandle>> =
        BTreeMap::new();
    for answer in probe_answers {
        handle(&answer.family_id, "survey.probe_answer.family_id")?;
        handle(
            &answer.observed_identity,
            "survey.probe_answer.observed_identity",
        )?;
        handle(&answer.answer, "survey.probe_answer.answer")?;
        let replaced = indexed
            .entry(answer.family_id.clone())
            .or_default()
            .insert(answer.observed_identity.clone(), answer.answer.clone());
        if replaced.is_some() {
            return Err(InstallationError::Duplicate {
                kind: "survey probe answer".to_owned(),
                identity: answer.observed_identity.as_str().to_owned(),
            });
        }
    }
    Ok(indexed)
}

fn validate_ascending(field: &str, values: &[PlatformHandle]) -> Result<(), InstallationError> {
    for value in values {
        handle(value, field)?;
    }
    for pair in values.windows(2) {
        if pair[0] >= pair[1] {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason: "must be sorted ascending and distinct".to_owned(),
            });
        }
    }
    Ok(())
}
