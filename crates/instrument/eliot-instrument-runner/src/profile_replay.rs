//! Parser replay over owner-verified immutable Testd stream bytes.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ClockReading, StateFence, sha256_hex};
use eliot_instrument_api::{EvidenceCoverage, RawEvidence, RawEvidenceSource, VerificationOutcome};
use eliot_instrument_nextest::{
    NEXTEST_INSTRUMENT, NEXTEST_STDOUT_CONTENT_TYPE, parse_jsonl, parse_list_json,
};
use eliot_testd_core::{
    EphemeralSourceBytes, InstrumentStageRequest, StageExecutionKind, TESTD_LIST_PROFILE,
    TestdEvaluationObservation, TestdEvaluationStatus, TestdParsingObservation, TestdParsingStatus,
    TestdStreamDisposition, TestdStreamEvidenceBinding,
};
use thiserror::Error;

use crate::{
    profile::{InstrumentRegistry, ProfileCompiler},
    registry::{ProviderRegistry, RegistryEntry, RegistryError, RegistryFreshness},
};

/// Parser/evaluator identities and result from replaying one immutable source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileReplayReceipt {
    /// SHA-256 of the exact verified source bytes consumed by the parser.
    pub source_sha256: String,
    /// Exact length of the verified source bytes consumed by the parser.
    pub source_byte_length: u64,
    /// Typed evidence-record identity the parsed source belongs to.
    pub source_evidence_identity: String,
    /// Owner-issued immutable-source readback receipt consumed by replay.
    pub source_readback_receipt_id: String,
    /// Parser observation suitable for applying to the exact typed stream.
    pub parsing: Option<TestdParsingObservation>,
    /// Evaluator observation suitable for applying after parsing succeeds.
    pub evaluation: Option<TestdEvaluationObservation>,
    /// Nextest's independently evaluated outcome, when this was a run stream.
    pub outcome: Option<VerificationOutcome>,
    /// Scope coverage returned by the real verifier, when evaluated.
    pub coverage: Option<EvidenceCoverage>,
    /// Human-readable parser/evaluator diagnostic, never itself authority.
    pub detail: Option<String>,
    /// True because only process terminal time exists as a conservative capture bound.
    pub terminal_clock_used_as_capture_bound: bool,
}

/// Typed refusal to replay a Testd stream under a stale or unsupported binding.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProfileReplayError {
    /// The retained stage request failed its own shape validation.
    #[error("retained stage request is invalid: {detail}")]
    InvalidStage { detail: String },
    /// Stage identities do not match the current registry selection.
    #[error("retained stage does not match the current registry selection: {field}")]
    StageMismatch { field: &'static str },
    /// Profile registry has moved since the stage was admitted.
    #[error("profile registry generation or digest is stale for the retained stage")]
    StaleProfileGeneration,
    /// Stage admission lacks the current provider-registry issuer material.
    #[error("retained stage has no provider-registry freshness issuer record")]
    MissingProviderFreshness,
    /// The provider registry could not resolve a current entry.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// Typed source binding is not an exact, complete verified readback.
    #[error("typed source is not replayable: {detail}")]
    SourceBinding { detail: String },
    /// Supplied ephemeral bytes disagree with the durable source binding.
    #[error("verified source bytes disagree with the retained digest or length")]
    SourceBytesMismatch,
    /// No productive parser/evaluator implementation exists for this profile.
    #[error("profile has no productive parser/evaluator replay owner: {profile}")]
    UnsupportedProfile { profile: String },
    /// The requested nextest stream has the wrong wire content type.
    #[error("nextest stream has an unsupported content type")]
    UnsupportedContentType,
    /// Evaluation cannot establish scope because the independent denominator is empty.
    #[error("canonical plan-required test set is empty")]
    EmptyRequiredTests,
    /// A source is bound to no valid ArtifactId for the existing verifier API.
    #[error("source digest cannot form a verifier artifact identity")]
    InvalidArtifactIdentity,
    /// The verifier rejected the exact raw evidence or clocks.
    #[error("nextest evaluator refused the replay: {detail}")]
    Evaluator { detail: String },
}

struct VerifiedSource<'a> {
    digest: &'a str,
    length: u64,
    readback_receipt_id: &'a str,
    fence: &'a StateFence,
}

/// Replays a complete owner-read-back stream through current profile and provider registries.
///
/// `stage.registry_generation` and `stage.registry_digest` belong to the
/// ProfileRegistry. Provider freshness is checked separately by
/// `ProviderRegistry::resolve_current` and is never compared across domains.
#[allow(clippy::too_many_arguments)]
pub fn replay_profile_stream(
    profile_registry: &InstrumentRegistry,
    provider_registry: &ProviderRegistry,
    freshness: &RegistryFreshness<'_>,
    stage: &InstrumentStageRequest,
    source: &TestdStreamEvidenceBinding,
    bytes: &EphemeralSourceBytes,
    required_test_ids: &BTreeSet<String>,
    started_at: ClockReading,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    stage
        .validate()
        .map_err(|error| ProfileReplayError::InvalidStage {
            detail: error.to_string(),
        })?;
    let (entry, parser_revision) =
        current_selection(profile_registry, provider_registry, freshness, stage)?;
    let verified = verify_source(source, bytes)?;
    if source.stream == eliot_process::ProcessStreamKind::Stderr {
        return stderr_receipt(source, verified, entry, parser_revision, finished_at);
    }
    if source.stream != eliot_process::ProcessStreamKind::Stdout {
        return Err(source_error(
            "only stdout and stderr are valid process streams",
        ));
    }
    if source.representation
        != Some(eliot_process::DurableStreamRepresentation::ExactTransportBytes)
    {
        return Err(ProfileReplayError::UnsupportedContentType);
    }
    if stage.profile_name == TESTD_LIST_PROFILE {
        return list_receipt(source, verified, bytes, entry, parser_revision, finished_at);
    }
    run_receipt(
        source,
        verified,
        bytes,
        stage,
        entry,
        parser_revision,
        required_test_ids,
        started_at,
        finished_at,
    )
}

fn current_selection<'a>(
    profile_registry: &InstrumentRegistry,
    provider_registry: &'a ProviderRegistry,
    freshness: &RegistryFreshness<'_>,
    stage: &InstrumentStageRequest,
) -> Result<(&'a RegistryEntry, String), ProfileReplayError> {
    let admitted = ProfileCompiler::new(profile_registry)
        .compile_exact(&stage.profile_name, stage.profile_revision)
        .map_err(|error| ProfileReplayError::InvalidStage {
            detail: error.to_string(),
        })?;
    if admitted.registry_generation != stage.registry_generation
        || admitted.registry_digest != stage.registry_digest
        || admitted.profile_digest != stage.profile_digest
        || admitted.dag_digest != stage.dag_digest
    {
        return Err(ProfileReplayError::StaleProfileGeneration);
    }
    let selected = admitted
        .stages
        .iter()
        .find(|candidate| candidate.stage_id == stage.stage_id)
        .ok_or(ProfileReplayError::StageMismatch { field: "stage_id" })?;
    for (matches, field) in [
        (selected.spec == stage.spec, "spec"),
        (
            selected.spec_revision == stage.spec_revision,
            "spec_revision",
        ),
        (selected.spec_digest == stage.spec_digest, "spec_digest"),
        (selected.kind == stage.kind, "kind"),
        (selected.parser == stage.parser, "parser"),
        (
            selected.parser_generation == stage.parser_generation,
            "parser_generation",
        ),
    ] {
        if !matches {
            return Err(ProfileReplayError::StageMismatch { field });
        }
    }
    let entry = provider_registry.resolve_current(&stage.invocation, freshness)?;
    let retained_freshness = stage
        .provider_freshness
        .as_ref()
        .ok_or(ProfileReplayError::MissingProviderFreshness)?;
    let current_fingerprints = freshness.fingerprints;
    if retained_freshness.generation != freshness.generation
        || retained_freshness.normative_pair_digest != freshness.normative_pair_digest
        || retained_freshness.fingerprints.source != current_fingerprints.source
        || retained_freshness.fingerprints.lock != current_fingerprints.lock
        || retained_freshness.fingerprints.toolchain != current_fingerprints.toolchain
        || retained_freshness.fingerprints.env != current_fingerprints.env
        || retained_freshness.fingerprints.exe != current_fingerprints.exe
        || retained_freshness.fingerprints.profile != current_fingerprints.profile
        || retained_freshness.fingerprints.parser != current_fingerprints.parser
        || entry.generation != freshness.generation
        || entry.normative_pair_digest != freshness.normative_pair_digest
        || entry.invalidation != *current_fingerprints
    {
        return Err(ProfileReplayError::StageMismatch {
            field: "provider_freshness",
        });
    }
    for (matches, field) in [
        (stage.adapter == entry.adapter, "adapter"),
        (
            stage.adapter_version == entry.adapter_version,
            "adapter_version",
        ),
        (stage.parser == entry.parser, "provider_parser"),
        (stage.evaluator == entry.evaluator, "evaluator"),
    ] {
        if !matches {
            return Err(ProfileReplayError::StageMismatch { field });
        }
    }
    if stage.execution != StageExecutionKind::Process
        || stage.kind != eliot_instrument_api::InstrumentKind::Test
        || entry.instrument.as_str() != NEXTEST_INSTRUMENT
    {
        return Err(ProfileReplayError::UnsupportedProfile {
            profile: stage.profile_name.clone(),
        });
    }
    Ok((entry, format!("generation:{}", selected.parser_generation)))
}

fn verify_source<'a>(
    source: &'a TestdStreamEvidenceBinding,
    bytes: &EphemeralSourceBytes,
) -> Result<VerifiedSource<'a>, ProfileReplayError> {
    source
        .validate()
        .map_err(|error| ProfileReplayError::SourceBinding {
            detail: error.to_string(),
        })?;
    if source.disposition != TestdStreamDisposition::CompleteSource {
        return Err(source_error("complete-source disposition is required"));
    }
    let digest = source
        .source_sha256
        .as_deref()
        .ok_or_else(|| source_error("complete source has no retained digest"))?;
    let length = source
        .source_byte_length
        .ok_or_else(|| source_error("complete source has no retained length"))?;
    let readback_receipt_id = source
        .readback_receipt_id
        .as_deref()
        .ok_or_else(|| source_error("complete source has no owner readback receipt"))?;
    let fence = source
        .fence
        .as_ref()
        .ok_or_else(|| source_error("complete source has no state fence"))?;
    if bytes.len() as u64 != length || sha256_hex(bytes.bytes()) != digest {
        return Err(ProfileReplayError::SourceBytesMismatch);
    }
    Ok(VerifiedSource {
        digest,
        length,
        readback_receipt_id,
        fence,
    })
}

fn stderr_receipt(
    source: &TestdStreamEvidenceBinding,
    verified: VerifiedSource<'_>,
    entry: &RegistryEntry,
    parser_revision: String,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    let parsing = parsing_observation(
        source,
        verified.readback_receipt_id,
        entry,
        parser_revision,
        TestdParsingStatus::NotApplicable,
        finished_at,
    )?;
    Ok(receipt_base(
        source,
        verified,
        Some(parsing),
        None,
        None,
        None,
        None,
    ))
}

fn list_receipt(
    source: &TestdStreamEvidenceBinding,
    verified: VerifiedSource<'_>,
    bytes: &EphemeralSourceBytes,
    entry: &RegistryEntry,
    parser_revision: String,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    let detail = parse_list_json(bytes.bytes())
        .err()
        .map(|error| error.to_string());
    let status = if detail.is_some() {
        TestdParsingStatus::ParseFailed
    } else {
        TestdParsingStatus::Parsed
    };
    let parsing = parsing_observation(
        source,
        verified.readback_receipt_id,
        entry,
        parser_revision,
        status,
        finished_at,
    )?;
    Ok(receipt_base(
        source,
        verified,
        Some(parsing),
        None,
        None,
        None,
        detail,
    ))
}

#[allow(clippy::too_many_arguments)]
fn run_receipt(
    source: &TestdStreamEvidenceBinding,
    verified: VerifiedSource<'_>,
    bytes: &EphemeralSourceBytes,
    stage: &InstrumentStageRequest,
    entry: &RegistryEntry,
    parser_revision: String,
    required_test_ids: &BTreeSet<String>,
    started_at: ClockReading,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    if required_test_ids.is_empty() {
        return Err(ProfileReplayError::EmptyRequiredTests);
    }
    let parser_id = entry.parser.to_string();
    let parsed = parse_jsonl(bytes.bytes());
    let Err(parse_error) = parsed else {
        return evaluate_run(
            source,
            verified,
            bytes,
            stage,
            entry,
            parser_id,
            parser_revision,
            required_test_ids,
            started_at,
            finished_at,
        );
    };
    let parsing = parsing_observation(
        source,
        verified.readback_receipt_id,
        entry,
        parser_revision,
        TestdParsingStatus::ParseFailed,
        finished_at,
    )?;
    Ok(receipt_base(
        source,
        verified,
        Some(parsing),
        None,
        None,
        None,
        Some(parse_error.to_string()),
    ))
}

#[allow(clippy::too_many_arguments)]
fn evaluate_run(
    source: &TestdStreamEvidenceBinding,
    verified: VerifiedSource<'_>,
    bytes: &EphemeralSourceBytes,
    stage: &InstrumentStageRequest,
    entry: &RegistryEntry,
    parser_id: String,
    parser_revision: String,
    required_test_ids: &BTreeSet<String>,
    started_at: ClockReading,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    let artifact_id = ArtifactId::new(format!("testd-stream-{}", verified.digest))
        .map_err(|_| ProfileReplayError::InvalidArtifactIdentity)?;
    let raw = RawEvidence {
        artifact_id,
        invocation_id: stage.invocation.request.request_id.clone(),
        source: RawEvidenceSource::Process,
        content_type: NEXTEST_STDOUT_CONTENT_TYPE.to_owned(),
        bytes: bytes.bytes().to_vec(),
        sha256: verified.digest.to_owned(),
        captured_at: finished_at,
        truncated: false,
    };
    let run = eliot_verifier::evaluate_current(
        &stage.invocation,
        &[raw],
        required_test_ids,
        started_at,
        finished_at,
    )
    .map_err(|error| ProfileReplayError::Evaluator {
        detail: error.to_string(),
    })?;
    let parsing = parsing_observation(
        source,
        verified.readback_receipt_id,
        entry,
        parser_revision.clone(),
        TestdParsingStatus::Parsed,
        finished_at,
    )?;
    let evaluation_status = match run.outcome {
        VerificationOutcome::Pass => TestdEvaluationStatus::Pass,
        VerificationOutcome::Fail => TestdEvaluationStatus::Fail,
        VerificationOutcome::Partial
        | VerificationOutcome::Blocked
        | VerificationOutcome::Cancelled
        | VerificationOutcome::Unknown => TestdEvaluationStatus::Inconclusive,
    };
    let evaluation = TestdEvaluationObservation::new(
        entry.evaluator.to_string(),
        entry.evaluator_version.to_string(),
        evaluation_status,
        "all-canonical-required-tests-passed",
        source.evidence_identity_sha256.clone(),
        parser_id,
        parser_revision,
        verified.digest,
        false,
        verified.fence.clone(),
        finished_at,
    )
    .map_err(|error| ProfileReplayError::Evaluator {
        detail: error.to_string(),
    })?;
    Ok(receipt_base(
        source,
        verified,
        Some(parsing),
        Some(evaluation),
        Some(run.outcome),
        Some(run.coverage),
        None,
    ))
}

fn parsing_observation(
    source: &TestdStreamEvidenceBinding,
    readback_receipt_id: &str,
    entry: &RegistryEntry,
    parser_revision: String,
    status: TestdParsingStatus,
    finished_at: ClockReading,
) -> Result<TestdParsingObservation, ProfileReplayError> {
    TestdParsingObservation::new(
        entry.parser.to_string(),
        parser_revision,
        status,
        source.evidence_identity_sha256.clone(),
        readback_receipt_id.to_owned(),
        false,
        finished_at,
    )
    .map_err(|error| source_error(error.to_string()))
}

fn receipt_base(
    source: &TestdStreamEvidenceBinding,
    verified: VerifiedSource<'_>,
    parsing: Option<TestdParsingObservation>,
    evaluation: Option<TestdEvaluationObservation>,
    outcome: Option<VerificationOutcome>,
    coverage: Option<EvidenceCoverage>,
    detail: Option<String>,
) -> ProfileReplayReceipt {
    ProfileReplayReceipt {
        source_sha256: verified.digest.to_owned(),
        source_byte_length: verified.length,
        source_evidence_identity: source.evidence_identity_sha256.clone(),
        source_readback_receipt_id: verified.readback_receipt_id.to_owned(),
        parsing,
        evaluation,
        outcome,
        coverage,
        detail,
        terminal_clock_used_as_capture_bound: true,
    }
}

fn source_error(detail: impl Into<String>) -> ProfileReplayError {
    ProfileReplayError::SourceBinding {
        detail: detail.into(),
    }
}
