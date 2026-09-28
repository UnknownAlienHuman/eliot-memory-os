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
//! would own it belongs to a different cell, so the probe stage is never
//! reached here: every observed identity is reported as `Withheld` at that
//! stage and nothing is executed. A non-empty catalogue `safe_probes` list is
//! a detection recipe, never permission to execute the discovered program.
//!
//! `I3.3.1` keeps this a detection-only surface. Nothing here asserts that
//! anything is installed, healthy, supported or admitted, and the
//! `discovered`, `declared`, `probed`, `admitted`, `degraded` and `unsupported`
//! states belong to `I3.3.1` and `I3.4`, not to a survey observation. An
//! existing `SurrealDB` process or installation stays an observation or import
//! candidate: this module records no adopt, reuse, kill or port decision, and
//! `I3.15` keeps the `InstallationTransaction` the single installation owner.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    InstallationError, IntegrationCategory, IntegrationDiscoveryCatalogue,
    IntegrationDiscoveryCatalogueEntry, PlatformHandle, handle,
};

/// The four mandatory survey stages, in their fixed probe order.
///
/// [`Self::ORDER`] is the single place that order is written down: the
/// traversal builds each stage's result under its own [`Self`] key and reads
/// them back through that slice, and [`InstallationSurvey::validate`] requires
/// the reported results to follow it, so a stage can never be visited out of
/// sequence or visited twice.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SurveyStage {
    /// Known configuration paths and manifests.
    KnownConfigOrManifest,
    /// PATH metadata.
    PathMetadata,
    /// Exact file version, signature and identity.
    FileVersionSignatureIdentity,
    /// A safe version or initialization probe, only after the identity stage.
    AdmittedSafeProbe,
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
    /// The probe stage's coverage outcome for this exact identity.
    ///
    /// Always [`SurveyStageOutcome::Withheld`]: this coordinator never runs a
    /// probe, so it never learns whether one succeeded.
    pub probe_outcome: SurveyStageOutcome,
    /// Answers a caller reported about a probe performed outside this
    /// coordinator, ascending.
    ///
    /// Evidence only. This coordinator neither performed those probes nor
    /// verified the answers, so a present answer is not evidence that anything
    /// was installed, launched or permitted to run; it is retained so the
    /// out-of-band observation is not lost.
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
    /// inputs that never resolved to a single identity. The per-identity probe
    /// outcome and the out-of-band answers live on [`Self::candidates`].
    pub stages: Vec<SurveyStageResult>,
    /// Distinct installations observed for this family, ascending by identity.
    pub candidates: Vec<SurveyCandidate>,
}

/// A probe answer a caller reports for a probe performed outside this
/// coordinator.
///
/// The survey retains the answer and re-derives nothing from it: this
/// coordinator has no execution port, so it neither ran the probe nor checked
/// that anything permitted it, and a well-formed answer is not a record that
/// anything was admitted to run.
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
}

impl InstallationSurvey {
    /// Validates stage order, coverage partitioning, alias ordering and the
    /// probe-stage candidate correspondence.
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
                // The probe stage is never reached for an identity here, so a
                // reported non-withheld probe outcome would claim a coverage
                // this coordinator never obtained.
                if candidate.probe_outcome != SurveyStageOutcome::Withheld {
                    return Err(InstallationError::IncompleteObservation(
                        "survey candidate reports a probe outcome this coordinator never reached"
                            .to_owned(),
                    ));
                }
            }
            validate_probe_stage_coverage(family)?;
        }
        Ok(())
    }
}

/// Surveys `catalogue` against `source` and returns the ordered report.
///
/// The catalogue is a set, so its entries are walked in ascending family order
/// and the source's per-stage observations are sorted before use: reordering
/// the catalogue or the observations cannot change the meaning of the result.
/// Stage order is mandatory and comes from [`SurveyStage::ORDER`], the probe
/// stage runs nothing, aliases coalesce by exact observed identity only, and
/// every unavailable input keeps its own coverage state. A probe answer naming
/// a family the catalogue does not contain is rejected, not dropped.
///
/// `catalogue` is validated before traversal and its [`InstallationError`]
/// surfaces unchanged; no second validation scheme applies here.
pub fn survey_installation(
    catalogue: &IntegrationDiscoveryCatalogue,
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

    // Fail closed: an answer bound to a family this catalogue does not contain
    // is consumed by no traversal step, so it is rejected rather than silently
    // dropped and degraded into an unprobed family.
    if let Some(orphan) = answers
        .keys()
        .find(|family_id| !ordered.contains_key(*family_id))
    {
        return Err(InstallationError::IncompleteObservation(format!(
            "survey probe answer names catalogue family {} that the catalogue does not contain",
            orphan.as_str()
        )));
    }

    let mut families = Vec::with_capacity(ordered.len());
    for (family_id, entry) in ordered {
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
    };
    survey.validate()?;
    Ok(survey)
}

fn survey_family(
    entry: &IntegrationDiscoveryCatalogueEntry,
    source: &dyn SurveyObservationSource,
    family_answers: &BTreeMap<PlatformHandle, PlatformHandle>,
) -> Result<SurveyFamilyReport, InstallationError> {
    // Each stage result is built by its own call and filed under its
    // `SurveyStage` key, so the reported order comes from `SurveyStage::ORDER`
    // alone instead of a second hand-written sequence.
    let mut results: BTreeMap<SurveyStage, SurveyStageResult> = BTreeMap::new();

    // Stage 1. The inspected inputs come from the catalogue, so an input the
    // source never reports is retained as not covered, never as absent.
    let known_observations = source.observe_known_config_or_manifest(entry)?;
    results.insert(
        SurveyStage::KnownConfigOrManifest,
        stage_result(
            SurveyStage::KnownConfigOrManifest,
            &known_observations,
            &entry.known_locations,
        )?,
    );

    // Stage 2. A PATH hit stays an observation about a name: this stage cannot
    // resolve an identity, and nothing here promotes it to one.
    let path_observations = source.observe_path_metadata(entry)?;
    results.insert(
        SurveyStage::PathMetadata,
        stage_result(SurveyStage::PathMetadata, &path_observations, &[])?,
    );

    // Stage 3. The only stage that resolves an exact observed identity, and it
    // always runs before the probe stage.
    let identity_stage = SurveyStage::FileVersionSignatureIdentity;
    let identity_observations = source.observe_file_identity(entry)?;
    results.insert(
        identity_stage,
        stage_result(identity_stage, &identity_observations, &[])?,
    );

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

    // Stage 4. Built from the candidates and runs nothing.
    results.insert(
        SurveyStage::AdmittedSafeProbe,
        probe_stage_result(&candidates),
    );

    let mut stages = Vec::with_capacity(SurveyStage::ORDER.len());
    for stage in SurveyStage::ORDER {
        let result = results.remove(&stage).ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "survey family did not build a result for a mandatory survey stage".to_owned(),
            )
        })?;
        stages.push(result);
    }

    Ok(SurveyFamilyReport {
        family_id: entry.family_id.clone(),
        category: entry.category,
        stages,
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
/// found. A stage with every bucket empty was asked about nothing and learned
/// nothing, so it reports `Withheld`: that is the one case where no bucket
/// gives a positive state, and an empty coverage set is never an absence.
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
        .map_or(SurveyStageOutcome::Withheld, |(_, outcome)| *outcome)
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
        // bucket, so a dropped input cannot be mistaken for an absence and an
        // input cannot be claimed by two buckets at once. Comparing bucket
        // lengths would accept a pair that off-sets one dropped input against
        // one extra entry, so the buckets are compared as the partition they
        // claim to be.
        let mut attributed = BTreeSet::new();
        for bucket in [
            &self.found,
            &self.not_found,
            &self.denied,
            &self.unreadable,
            &self.ambiguous,
            &self.withheld,
        ] {
            for value in bucket {
                if !attributed.insert(value) {
                    return Err(InstallationError::IncompleteObservation(
                        "survey stage buckets claim the same input twice".to_owned(),
                    ));
                }
            }
        }
        if !inputs.is_subset(&attributed) {
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
        // A reported answer is carried as evidence only: it says nothing about
        // whether the probe stage was reached, so the per-identity probe
        // outcome stays `Withheld` whatever the caller supplied.
        let answer = family_answers.get(&observed_identity).cloned();
        candidates.push(SurveyCandidate {
            observed_identity,
            aliases: inputs.into_iter().collect(),
            probe_outcome: SurveyStageOutcome::Withheld,
            probe_answers: answer.into_iter().collect(),
        });
    }
    candidates
}

/// Builds the probe stage result without running anything.
///
/// The probe stage has no execution port here, so it is never reached: every
/// observed identity is `Withheld`, with or without a caller-reported answer.
/// The answers are still retained in the stage's evidence so the out-of-band
/// observation is not lost, and an empty candidate set is also `Withheld`,
/// because a stage that was asked about nothing learned nothing.
fn probe_stage_result(candidates: &[SurveyCandidate]) -> SurveyStageResult {
    let mut withheld = BTreeSet::new();
    let mut evidence = BTreeSet::new();
    for candidate in candidates {
        withheld.insert(candidate.observed_identity.clone());
        evidence.extend(candidate.probe_answers.iter().cloned());
    }
    let mut result = SurveyStageResult {
        stage: SurveyStage::AdmittedSafeProbe,
        outcome: SurveyStageOutcome::Withheld,
        inputs: candidates
            .iter()
            .map(|candidate| candidate.observed_identity.clone())
            .collect(),
        found: Vec::new(),
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
///
/// The probe stage was never run, so it must withhold every observed identity
/// and nothing else: an identity the stage never reached, or a withheld
/// identity no candidate observed, would both be a coverage claim this
/// coordinator cannot make.
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
    let identities = family
        .candidates
        .iter()
        .map(|candidate| candidate.observed_identity.clone())
        .collect::<BTreeSet<_>>();
    let withheld = probe.withheld.iter().cloned().collect::<BTreeSet<_>>();
    let asked = probe.inputs.iter().cloned().collect::<BTreeSet<_>>();
    if asked != identities || withheld != identities {
        return Err(InstallationError::IncompleteObservation(
            "survey probe stage does not withhold exactly its observed candidates".to_owned(),
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
