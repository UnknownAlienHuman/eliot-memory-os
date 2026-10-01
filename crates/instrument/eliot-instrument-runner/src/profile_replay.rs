//! Parser replay over owner-verified immutable Testd stream bytes.
//!
//! This is the replay half of the governed profile path: the caller supplies
//! the exact retained stage, current provider registry/freshness, typed stream
//! binding, and ephemeral bytes returned by successful source readback. The
//! module never resolves a second adapter map, reads a legacy handle, or
//! treats a process exit status as a verification result.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ClockReading, sha256_hex};
use eliot_instrument_api::{
    EvidenceCoverage, RawEvidence, RawEvidenceSource, VerificationOutcome,
};
use eliot_instrument_nextest::{
    NEXTEST_INSTRUMENT, NEXTEST_STDOUT_CONTENT_TYPE, parse_jsonl, parse_list_json,
};
use eliot_testd_core::{
    EphemeralSourceBytes, InstrumentStageRequest, StageExecutionKind,
    TestdEvaluationObservation, TestdEvaluationStatus, TestdParsingObservation,
    TestdParsingStatus, TestdStreamDisposition, TestdStreamEvidenceBinding,
    TESTD_LIST_PROFILE,
};
use thiserror::Error;

use crate::registry::{ProviderRegistry, RegistryError, RegistryFreshness};

/// Parser/evaluator identities and result from replaying one immutable source.
///
/// `terminal_clock_used_as_capture_bound` is true because current process
/// evidence does not retain a per-stream capture clock. `finished_at` is the
/// observed process terminal boundary; the owner readback clock is never used
/// as a capture timestamp.
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
    /// The terminal process observation was used as the conservative capture
    /// bound because there is no exact per-stream capture clock in the record.
    pub terminal_clock_used_as_capture_bound: bool,
}

/// Typed refusal to replay a Testd stream under a stale or unsupported binding.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProfileReplayError {
    /// The retained stage request failed its own shape validation.
    #[error("retained stage request is invalid: {detail}")]
    InvalidStage { detail: String },
    /// Stage identities do not match the current registry selection.
    #[error("retained stage does not match the current provider entry: {field}")]
    StageMismatch { field: &'static str },
    /// The stage request names a provider registry generation that is no
    /// longer current.
    #[error("provider registry generation is stale for the retained stage")]
    StaleStageGeneration,
    /// The provider registry could not resolve a current entry.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// Typed source binding is not an exact, complete verified readback.
    #[error("typed source is not replayable: {detail}")]
    SourceBinding { detail: String },
    /// Supplied ephemeral bytes disagree with the durable source binding.
    #[error("verified source bytes disagree with the retained digest or length")]
    SourceBytesMismatch,
    /// The stream has no registered parser/evaluator implementation in this
    /// runner build.
    #[error("profile has no productive parser/evaluator replay owner: {profile}")]
    UnsupportedProfile { profile: String },
    /// The requested nextest stream has the wrong wire content type.
    #[error("nextest stream has an unsupported content type")]
    UnsupportedContentType,
    /// Evaluation cannot establish scope because the independent denominator
    /// is empty.
    #[error("canonical plan-required test set is empty")]
    EmptyRequiredTests,
    /// A source is bound to no valid ArtifactId for the existing verifier API.
    #[error("source digest cannot form a verifier artifact identity")]
    InvalidArtifactIdentity,
    /// The verifier rejected the exact raw evidence or clocks.
    #[error("nextest evaluator refused the replay: {detail}")]
    Evaluator { detail: String },
}

/// Replays one complete, owner-read-back stream through the current provider
/// registry's real parser/evaluator binding.
///
/// The provider registry digest is deliberately not compared with
/// `stage.registry_digest`: that stage field is the admitted ProfileRegistry
/// digest. Current provider freshness is established by
/// `ProviderRegistry::resolve_current` using the separately supplied
/// `RegistryFreshness` values.
#[allow(clippy::too_many_arguments)]
pub fn replay_profile_stream(
    registry: &ProviderRegistry,
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
    if stage.registry_generation != freshness.generation
        || registry.generation() != freshness.generation
    {
        return Err(ProfileReplayError::StaleStageGeneration);
    }
    let entry = registry.resolve_current(&stage.invocation, freshness)?;
    if stage.adapter != entry.adapter {
        return Err(ProfileReplayError::StageMismatch { field: "adapter" });
    }
    if stage.adapter_version != entry.adapter_version {
        return Err(ProfileReplayError::StageMismatch {
            field: "adapter_version",
        });
    }
    if stage.parser != entry.parser {
        return Err(ProfileReplayError::StageMismatch { field: "parser" });
    }
    if stage.evaluator != entry.evaluator {
        return Err(ProfileReplayError::StageMismatch { field: "evaluator" });
    }
    if stage.execution != StageExecutionKind::Process
        || stage.kind != eliot_instrument_api::InstrumentKind::Test
        || entry.instrument.as_str() != NEXTEST_INSTRUMENT
    {
        return Err(ProfileReplayError::UnsupportedProfile {
            profile: stage.profile_name.clone(),
        });
    }

    source
        .validate()
        .map_err(|error| ProfileReplayError::SourceBinding {
            detail: error.to_string(),
        })?;
    if source.disposition != TestdStreamDisposition::CompleteSource
        || source.readback_receipt_id.is_none()
        || source.fence.is_none()
    {
        return Err(ProfileReplayError::SourceBinding {
            detail: "replay requires a complete source with an owner receipt and fence".to_owned(),
        });
    }
    let expected_digest = source
        .source_sha256
        .as_deref()
        .expect("complete-source validation requires source digest");
    let expected_length = source
        .source_byte_length
        .expect("complete-source validation requires source length");
    if bytes.len() as u64 != expected_length || sha256_hex(bytes.bytes()) != expected_digest {
        return Err(ProfileReplayError::SourceBytesMismatch);
    }
    let readback_receipt_id = source
        .readback_receipt_id
        .clone()
        .expect("complete-source validation requires readback receipt");
    let parser_id = entry.parser.to_string();
    let parser_revision = format!("parser-generation:{}", stage.parser_generation);

    if source.stream == eliot_process::ProcessStreamKind::Stderr {
        let parsing = TestdParsingObservation::new(
            parser_id,
            parser_revision,
            TestdParsingStatus::NotApplicable,
            source.evidence_identity_sha256.clone(),
            readback_receipt_id.clone(),
            false,
            finished_at,
        )
        .map_err(|error| ProfileReplayError::SourceBinding {
            detail: error.to_string(),
        })?;
        return Ok(ProfileReplayReceipt {
            source_sha256: expected_digest.to_owned(),
            source_byte_length: expected_length,
            source_evidence_identity: source.evidence_identity_sha256.clone(),
            source_readback_receipt_id: readback_receipt_id,
            parsing: Some(parsing),
            evaluation: None,
            outcome: None,
            coverage: None,
            detail: Some("nextest run events are parsed from stdout only".to_owned()),
            terminal_clock_used_as_capture_bound: true,
        });
    }
    if source.stream != eliot_process::ProcessStreamKind::Stdout {
        return Err(ProfileReplayError::SourceBinding {
            detail: "only stdout and stderr are valid process streams".to_owned(),
        });
    }
    if source.representation != Some(eliot_process::DurableStreamRepresentation::ExactTransportBytes)
    {
        return Err(ProfileReplayError::UnsupportedContentType);
    }

    if stage.profile_name == TESTD_LIST_PROFILE {
        let parse_detail = parse_list_json(bytes.bytes()).err();
        let status = if parse_detail.is_none() {
            TestdParsingStatus::Parsed
        } else {
            TestdParsingStatus::ParseFailed
        };
        let parsing = TestdParsingObservation::new(
            parser_id,
            parser_revision,
            status,
            source.evidence_identity_sha256.clone(),
            readback_receipt_id.clone(),
            false,
            finished_at,
        )
        .map_err(|error| ProfileReplayError::SourceBinding {
            detail: error.to_string(),
        })?;
        return Ok(ProfileReplayReceipt {
            source_sha256: expected_digest.to_owned(),
            source_byte_length: expected_length,
            source_evidence_identity: source.evidence_identity_sha256.clone(),
            source_readback_receipt_id: readback_receipt_id,
            parsing: Some(parsing),
            evaluation: None,
            outcome: None,
            coverage: None,
            detail: parse_detail.map(|error| error.to_string()),
            terminal_clock_used_as_capture_bound: true,
        });
    }
    if required_test_ids.is_empty() {
        return Err(ProfileReplayError::EmptyRequiredTests);
    }

    let artifact_id = ArtifactId::new(format!("testd-stream-{}", expected_digest))
        .map_err(|_| ProfileReplayError::InvalidArtifactIdentity)?;
    let raw = RawEvidence {
        artifact_id,
        invocation_id: stage.invocation.request.request_id.clone(),
        source: RawEvidenceSource::Process,
        content_type: NEXTEST_STDOUT_CONTENT_TYPE.to_owned(),
        bytes: bytes.bytes().to_vec(),
        sha256: expected_digest.to_owned(),
        captured_at: finished_at,
        truncated: false,
    };

    let run = match parse_jsonl(bytes.bytes()) {
        Ok(_) => eliot_verifier::evaluate_current(
            &stage.invocation,
            &[raw],
            required_test_ids,
            started_at,
            finished_at,
        ),
        Err(error) => {
            let parsing = TestdParsingObservation::new(
                parser_id,
                parser_revision,
                TestdParsingStatus::ParseFailed,
                source.evidence_identity_sha256.clone(),
                source
                    .readback_receipt_id
                    .clone()
                    .expect("complete-source validation requires readback receipt"),
                false,
                finished_at,
            )
            .map_err(|core| ProfileReplayError::SourceBinding {
                detail: core.to_string(),
            })?;
            return Ok(ProfileReplayReceipt {
                source_sha256: expected_digest.to_owned(),
                source_byte_length: expected_length,
                source_evidence_identity: source.evidence_identity_sha256.clone(),
                source_readback_receipt_id: source
                    .readback_receipt_id
                    .clone()
                    .expect("complete-source validation requires readback receipt"),
                parsing: Some(parsing),
                evaluation: None,
                outcome: None,
                coverage: None,
                detail: Some(error.to_string()),
                terminal_clock_used_as_capture_bound: true,
            });
        }
    }
    .map_err(|error| ProfileReplayError::Evaluator {
        detail: error.to_string(),
    })?;

    let parsing = TestdParsingObservation::new(
        parser_id.clone(),
        parser_revision.clone(),
        TestdParsingStatus::Parsed,
        source.evidence_identity_sha256.clone(),
        readback_receipt_id.clone(),
        false,
        finished_at,
    )
    .map_err(|error| ProfileReplayError::SourceBinding {
        detail: error.to_string(),
    })?;
    let evaluator_status = match run.outcome {
        VerificationOutcome::Pass => TestdEvaluationStatus::Pass,
        VerificationOutcome::Fail => TestdEvaluationStatus::Fail,
        VerificationOutcome::Partial
        | VerificationOutcome::Blocked
        | VerificationOutcome::Cancelled
        | VerificationOutcome::Unknown => TestdEvaluationStatus::Inconclusive,
    };
    let evaluation = TestdEvaluationObservation::new(
        entry.evaluator.to_string(),
        format!(
            "provider-generation:{};adapter-version:{}",
            entry.generation, entry.adapter_version
        ),
        evaluator_status,
        "all-canonical-required-tests-passed",
        source.evidence_identity_sha256.clone(),
        parser_id,
        parser_revision,
        expected_digest,
        false,
        source
            .fence
            .clone()
            .expect("complete-source validation requires readback fence"),
        finished_at,
    )
    .map_err(|error| ProfileReplayError::Evaluator {
        detail: error.to_string(),
    })?;

    Ok(ProfileReplayReceipt {
        source_sha256: expected_digest.to_owned(),
        source_byte_length: expected_length,
        source_evidence_identity: source.evidence_identity_sha256.clone(),
        source_readback_receipt_id: readback_receipt_id,
        parsing: Some(parsing),
        evaluation: Some(evaluation),
        outcome: Some(run.outcome),
        coverage: Some(run.coverage),
        detail: None,
        terminal_clock_used_as_capture_bound: true,
    })
}
