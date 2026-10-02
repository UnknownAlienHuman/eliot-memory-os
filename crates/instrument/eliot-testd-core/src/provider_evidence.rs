//! Provider parser evidence bound to TestD's original retained registry and
//! raw process output. Parsing is descriptive; it never evaluates a task.

use eliot_instrument_api::{EvidenceCoverage, ExecutionStatus, VerificationOutcome};
use serde::{Deserialize, Serialize};

use crate::{
    RawArtifact, RawArtifactStream, TESTD_LIST_PROFILE, TESTD_PRODUCTIVE_PROFILE,
    TESTD_SCOPED_PROFILE, TestJob, TestdArtifactBinding, TestdError, TestdEvaluatorSlot,
    TestdParserSlot, TestdParsingStatus, TestdProcessEvidenceBundle,
};
use eliot_process::{ProcessStreamKind, StreamPersistenceStatus, StreamTransportStatus};

const REGISTRY_CONTENT_TYPE: &str = "application/vnd.eliot.provider-registry+json";
const RUN_CONTENT_TYPE: &str = "application/x-nextest-libtest-json-plus";
const LIST_CONTENT_TYPE: &str = "application/x-nextest-list-json";
const NEXTTEST_INSTRUMENT: &str = eliot_instrument_nextest::NEXTEST_INSTRUMENT;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderContractIdentity {
    pub id: String,
    /// A component revision is recorded only when the retained original
    /// registry has one. The registry currently names only the parser image
    /// digest; it does not publish independent normalizer/evaluator/verifier
    /// revisions.
    pub revision: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentitySet {
    pub profile_id: String,
    pub profile_revision: String,
    pub adapter_id: String,
    pub adapter_revision: String,
    pub parser: ProviderContractIdentity,
    pub normalizer: ProviderContractIdentity,
    pub evaluator: ProviderContractIdentity,
    pub verifier: ProviderContractIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRawSource {
    pub handle: String,
    pub sha256: String,
    pub length: u64,
    pub content_type: String,
    pub truncated: bool,
    pub process_evidence_index: Option<usize>,
    pub observed_bytes: Option<u64>,
    pub transport: Option<StreamTransportStatus>,
    pub persistence: Option<StreamPersistenceStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ParsedProviderOutput {
    Run {
        started: u32,
        completed: u32,
        passed: u32,
        failed: u32,
        skipped: u32,
        timed_out: u32,
        leaked: u32,
        cancelled: u32,
    },
    List {
        declared_count: u64,
        observed_count: u64,
    },
}

/// A parser result kept separate from execution, evaluation, verification,
/// artifact binding, independence, and coverage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdProviderEvidence {
    pub job_id: String,
    pub operation_id: String,
    pub profile: String,
    pub registry_handle: String,
    pub registry_sha256: String,
    pub registry_length: u64,
    pub identities: ProviderIdentitySet,
    pub source: Option<ProviderRawSource>,
    pub parser: TestdParserSlot,
    pub parsed: Option<ParsedProviderOutput>,
    pub evaluator: TestdEvaluatorSlot,
    pub artifact_binding: TestdArtifactBinding,
    pub execution: ExecutionStatus,
    pub verifier_outcome: VerificationOutcome,
    pub coverage: EvidenceCoverage,
    pub independence: ProviderIndependence,
    pub cleanup: ProviderCleanupStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderIndependence {
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderCleanupStatus {
    Unknown,
}

#[derive(Deserialize)]
struct SnapshotView {
    job_id: String,
    operation_id: String,
    profile: String,
    invocation_target: String,
    invocation_arguments: Vec<String>,
    source_root: String,
    target_root: String,
    cache_root: String,
    original: SnapshotOriginal,
    metadata: SnapshotMetadata,
}

#[derive(Deserialize)]
struct SnapshotOriginal {
    parser_image_sha256: String,
}

#[derive(Deserialize)]
struct SnapshotMetadata {
    profile: String,
    profile_version: String,
    instrument: String,
    adapter: String,
    adapter_version: String,
    parser: String,
    normalizer: String,
    evaluator: String,
    verifier: String,
    supports_test: bool,
}

impl TestdProviderEvidence {
    /// Parses the sole supported stdout stream after the owner has retained it.
    /// An absent, empty, or truncated stream is carried as unavailable.
    pub fn from_receipt_inputs(
        job: &TestJob,
        execution: ExecutionStatus,
        registry: &RawArtifact,
        raw_artifacts: &[RawArtifact],
        typed_evidence: &[TestdProcessEvidenceBundle],
        stdout_process_index: Option<usize>,
    ) -> Result<Option<Self>, TestdError> {
        let profile = job.invocation.profile.as_str();
        if !matches!(
            profile,
            TESTD_PRODUCTIVE_PROFILE | TESTD_LIST_PROFILE | TESTD_SCOPED_PROFILE
        ) {
            return Ok(None);
        }
        let metadata = retained_metadata(registry, job)?;
        let identities = provider_identities(metadata);
        let (source, parser, parsed, artifact_binding) = parse_provider_source(
            profile,
            &identities,
            raw_artifacts,
            typed_evidence,
            stdout_process_index,
            job,
        )?;
        let evidence = Self {
            job_id: job.job_id.clone(),
            operation_id: job.process.operation_id.clone(),
            profile: profile.to_owned(),
            registry_handle: registry.handle.clone(),
            registry_sha256: registry.sha256.clone(),
            registry_length: registry.length,
            identities,
            source,
            parser,
            parsed,
            evaluator: TestdEvaluatorSlot::unassessed(),
            artifact_binding,
            execution,
            verifier_outcome: VerificationOutcome::Unknown,
            coverage: EvidenceCoverage::Unknown,
            independence: ProviderIndependence::Unknown,
            cleanup: ProviderCleanupStatus::Unknown,
        };
        evidence.validate_against(job, registry, raw_artifacts, typed_evidence)?;
        Ok(Some(evidence))
    }

    /// Rebinds every identity and source reference to the exact original bytes.
    pub fn validate_against(
        &self,
        job: &TestJob,
        registry: &RawArtifact,
        raw_artifacts: &[RawArtifact],
        typed_evidence: &[TestdProcessEvidenceBundle],
    ) -> Result<(), TestdError> {
        let metadata = retained_metadata(registry, job)?;
        if !self.identity_matches(job, registry, &metadata) {
            return Err(TestdError::InvalidBinding);
        }
        self.parser
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        validate_provider_source(self, job, raw_artifacts, typed_evidence)
    }

    fn identity_matches(
        &self,
        job: &TestJob,
        registry: &RawArtifact,
        metadata: &RetainedMetadata,
    ) -> bool {
        self.job_id == job.job_id
            && self.operation_id == job.process.operation_id
            && self.profile == job.invocation.profile
            && self.registry_handle == registry.handle
            && self.registry_sha256 == registry.sha256
            && self.registry_length == registry.length
            && self.identities == provider_identities(metadata.clone())
            && self.verifier_outcome == VerificationOutcome::Unknown
            && self.coverage == EvidenceCoverage::Unknown
            && self.evaluator == TestdEvaluatorSlot::unassessed()
            && self.independence == ProviderIndependence::Unknown
            && self.cleanup == ProviderCleanupStatus::Unknown
    }
}

fn source_matches_complete_stream(
    source: &ProviderRawSource,
    artifact: &RawArtifact,
    job: &TestJob,
    typed_evidence: &[TestdProcessEvidenceBundle],
) -> bool {
    let Some(process_evidence_index) = source.process_evidence_index else {
        return false;
    };
    let Some(bundle) = typed_evidence.get(process_evidence_index) else {
        return false;
    };
    let Some(stream) = bundle.stdout.binding.as_ref() else {
        return false;
    };
    bundle.binding.job_id().as_str() == job.job_id
        && bundle.binding.operation_id().as_str() == job.process.operation_id
        && bundle.binding.process_tree_id().as_str() == job.process.process_tree_id
        && bundle.stdout.stream == ProcessStreamKind::Stdout
        && stream.stream == ProcessStreamKind::Stdout
        && stream.transport == StreamTransportStatus::Complete
        && source.transport == Some(stream.transport)
        && source.persistence == Some(stream.persistence)
        && source.observed_bytes == Some(stream.observed_bytes)
        && artifact.length == stream.observed_bytes
        && crate::sha256_hex(&artifact.bytes) == stream.observed_sha256
        && !artifact.truncated
}

fn expected_content_type(profile: &str) -> &'static str {
    if profile == TESTD_LIST_PROFILE {
        LIST_CONTENT_TYPE
    } else {
        RUN_CONTENT_TYPE
    }
}

fn is_parseable_stdout(artifact: &RawArtifact, expected_content_type: &str) -> bool {
    !artifact.truncated
        && !artifact.bytes.is_empty()
        && artifact.content_type == expected_content_type
}

#[derive(Clone)]
struct RetainedMetadata {
    profile: String,
    profile_version: String,
    adapter: String,
    adapter_version: String,
    parser: String,
    parser_image_sha256: String,
    normalizer: String,
    evaluator: String,
    verifier: String,
}

fn provider_identities(metadata: RetainedMetadata) -> ProviderIdentitySet {
    ProviderIdentitySet {
        profile_id: metadata.profile,
        profile_revision: metadata.profile_version,
        adapter_id: metadata.adapter,
        adapter_revision: metadata.adapter_version,
        parser: ProviderContractIdentity {
            id: metadata.parser,
            revision: Some(metadata.parser_image_sha256),
        },
        normalizer: ProviderContractIdentity {
            id: metadata.normalizer,
            revision: None,
        },
        evaluator: ProviderContractIdentity {
            id: metadata.evaluator,
            revision: None,
        },
        verifier: ProviderContractIdentity {
            id: metadata.verifier,
            revision: None,
        },
    }
}

fn parse_provider_source(
    profile: &str,
    identities: &ProviderIdentitySet,
    raw_artifacts: &[RawArtifact],
    typed_evidence: &[TestdProcessEvidenceBundle],
    stdout_process_index: Option<usize>,
    job: &TestJob,
) -> Result<
    (
        Option<ProviderRawSource>,
        TestdParserSlot,
        Option<ParsedProviderOutput>,
        TestdArtifactBinding,
    ),
    TestdError,
> {
    let mut stdout = raw_artifacts
        .iter()
        .filter(|artifact| artifact.stream == RawArtifactStream::Stdout);
    let Some(artifact) = stdout.next() else {
        return Ok((
            None,
            unavailable_parser(),
            None,
            TestdArtifactBinding::Unbound,
        ));
    };
    if stdout.next().is_some() {
        return Err(TestdError::InvalidBinding);
    }
    artifact.validate()?;
    let stream = stdout_process_index
        .and_then(|index| typed_evidence.get(index))
        .and_then(|bundle| bundle.stdout.binding.as_ref());
    let source = ProviderRawSource {
        handle: artifact.handle.clone(),
        sha256: artifact.sha256.clone(),
        length: artifact.length,
        content_type: artifact.content_type.clone(),
        truncated: artifact.truncated,
        process_evidence_index: stdout_process_index,
        observed_bytes: stream.map(|value| value.observed_bytes),
        transport: stream.map(|value| value.transport),
        persistence: stream.map(|value| value.persistence),
    };
    if stream.is_none()
        || !is_parseable_stdout(artifact, expected_content_type(profile))
        || !source_matches_complete_stream(&source, artifact, job, typed_evidence)
    {
        return Ok((
            Some(source),
            unavailable_parser(),
            None,
            TestdArtifactBinding::Unbound,
        ));
    }
    let binding = TestdArtifactBinding::BoundExact(artifact.handle.clone());
    match parse_retained_output(profile, &artifact.bytes) {
        Ok(parsed) => Ok((
            Some(source),
            executed_parser(identities),
            Some(parsed),
            binding,
        )),
        Err(_) => Ok((Some(source), failed_parser(identities), None, binding)),
    }
}

fn validate_provider_source(
    evidence: &TestdProviderEvidence,
    job: &TestJob,
    raw_artifacts: &[RawArtifact],
    typed_evidence: &[TestdProcessEvidenceBundle],
) -> Result<(), TestdError> {
    let stdout_count = raw_artifacts
        .iter()
        .filter(|artifact| artifact.stream == RawArtifactStream::Stdout)
        .count();
    if stdout_count > 1 || (stdout_count == 1) != evidence.source.is_some() {
        return Err(TestdError::InvalidBinding);
    }
    let source_artifact = find_source_artifact(evidence, job, raw_artifacts, typed_evidence)?;
    match (
        evidence.parser.status,
        source_artifact,
        &evidence.parsed,
        &evidence.artifact_binding,
    ) {
        (
            TestdParsingStatus::Parsed,
            Some((artifact, source)),
            Some(parsed),
            TestdArtifactBinding::BoundExact(handle),
        ) if handle == &artifact.handle
            && evidence.parser.parser_id.as_deref()
                == Some(evidence.identities.parser.id.as_str())
            && evidence.parser.parser_revision == evidence.identities.parser.revision
            && is_parseable_stdout(artifact, expected_content_type(&evidence.profile))
            && source_matches_complete_stream(source, artifact, job, typed_evidence)
            && parse_retained_output(&evidence.profile, &artifact.bytes)
                .ok()
                .as_ref()
                == Some(parsed) =>
        {
            Ok(())
        }
        (
            TestdParsingStatus::ParseFailed,
            Some((artifact, source)),
            None,
            TestdArtifactBinding::BoundExact(handle),
        ) if handle == &artifact.handle
            && evidence.parser.parser_id.as_deref()
                == Some(evidence.identities.parser.id.as_str())
            && evidence.parser.parser_revision == evidence.identities.parser.revision
            && is_parseable_stdout(artifact, expected_content_type(&evidence.profile))
            && source_matches_complete_stream(source, artifact, job, typed_evidence)
            && parse_retained_output(&evidence.profile, &artifact.bytes).is_err() =>
        {
            Ok(())
        }
        (TestdParsingStatus::SourceUnavailable, source, None, TestdArtifactBinding::Unbound)
            if evidence.parser.parser_id.is_none()
                && evidence.parser.parser_revision.is_none()
                && source.is_none_or(|(artifact, source)| {
                    !is_parseable_stdout(artifact, expected_content_type(&evidence.profile))
                        || !source_matches_complete_stream(source, artifact, job, typed_evidence)
                }) =>
        {
            Ok(())
        }
        _ => Err(TestdError::InvalidBinding),
    }
}

fn find_source_artifact<'a>(
    evidence: &'a TestdProviderEvidence,
    job: &TestJob,
    raw_artifacts: &'a [RawArtifact],
    typed_evidence: &[TestdProcessEvidenceBundle],
) -> Result<Option<(&'a RawArtifact, &'a ProviderRawSource)>, TestdError> {
    let Some(source) = evidence.source.as_ref() else {
        return Ok(None);
    };
    let mut matching = raw_artifacts.iter().filter(|artifact| {
        artifact.handle == source.handle
            && artifact.sha256 == source.sha256
            && artifact.length == source.length
            && artifact.content_type == source.content_type
            && artifact.truncated == source.truncated
            && artifact.stream == RawArtifactStream::Stdout
    });
    let artifact = matching.next().ok_or(TestdError::InvalidBinding)?;
    if matching.next().is_some() {
        return Err(TestdError::InvalidBinding);
    }
    artifact.validate()?;
    match source.process_evidence_index {
        Some(index) => {
            let stream = typed_evidence
                .get(index)
                .and_then(|bundle| bundle.stdout.binding.as_ref());
            match stream {
                Some(stream)
                    if stream.stream == ProcessStreamKind::Stdout
                        && Some(stream.observed_bytes) == source.observed_bytes
                        && Some(stream.transport) == source.transport
                        && Some(stream.persistence) == source.persistence
                        && source_matches_process_binding(source, job, typed_evidence) => {}
                None if evidence.parser.status == TestdParsingStatus::SourceUnavailable
                    && source.observed_bytes.is_none()
                    && source.transport.is_none()
                    && source.persistence.is_none()
                    && source_matches_process_slot(source, job, typed_evidence) => {}
                _ => return Err(TestdError::InvalidBinding),
            }
        }
        None if evidence.parser.status == TestdParsingStatus::SourceUnavailable
            && source.observed_bytes.is_none()
            && source.transport.is_none()
            && source.persistence.is_none() => {}
        None => return Err(TestdError::InvalidBinding),
    }
    Ok(Some((artifact, source)))
}

fn source_matches_process_binding(
    source: &ProviderRawSource,
    job: &TestJob,
    typed_evidence: &[TestdProcessEvidenceBundle],
) -> bool {
    source
        .process_evidence_index
        .and_then(|index| typed_evidence.get(index))
        .is_some_and(|bundle| {
            bundle.binding.job_id().as_str() == job.job_id
                && bundle.binding.operation_id().as_str() == job.process.operation_id
                && bundle.binding.process_tree_id().as_str() == job.process.process_tree_id
                && bundle.stdout.stream == ProcessStreamKind::Stdout
        })
}

fn source_matches_process_slot(
    source: &ProviderRawSource,
    job: &TestJob,
    typed_evidence: &[TestdProcessEvidenceBundle],
) -> bool {
    source
        .process_evidence_index
        .and_then(|index| typed_evidence.get(index))
        .is_some_and(|bundle| {
            bundle.binding.job_id().as_str() == job.job_id
                && bundle.binding.operation_id().as_str() == job.process.operation_id
                && bundle.binding.process_tree_id().as_str() == job.process.process_tree_id
                && bundle.stdout.stream == ProcessStreamKind::Stdout
                && bundle.stdout.binding.is_none()
                && bundle.stdout.disposition == crate::TestdStreamDisposition::StreamNotEmitted
        })
}

fn unavailable_parser() -> TestdParserSlot {
    TestdParserSlot {
        parser_id: None,
        parser_revision: None,
        status: TestdParsingStatus::SourceUnavailable,
    }
}

fn executed_parser(identities: &ProviderIdentitySet) -> TestdParserSlot {
    TestdParserSlot {
        parser_id: Some(identities.parser.id.clone()),
        parser_revision: identities.parser.revision.clone(),
        status: TestdParsingStatus::Parsed,
    }
}

fn failed_parser(identities: &ProviderIdentitySet) -> TestdParserSlot {
    TestdParserSlot {
        status: TestdParsingStatus::ParseFailed,
        ..executed_parser(identities)
    }
}

fn retained_metadata(
    registry: &RawArtifact,
    job: &TestJob,
) -> Result<RetainedMetadata, TestdError> {
    registry.validate()?;
    if registry.truncated
        || registry.content_type != REGISTRY_CONTENT_TYPE
        || registry.handle != format!("provider-registry:{}", job.process.operation_id)
    {
        return Err(TestdError::InvalidBinding);
    }
    retained_metadata_from_bytes(&registry.bytes, job)
}

fn retained_metadata_from_bytes(
    bytes: &[u8],
    job: &TestJob,
) -> Result<RetainedMetadata, TestdError> {
    let snapshot: SnapshotView =
        serde_json::from_slice(bytes).map_err(|error| TestdError::Corrupt(error.to_string()))?;
    if snapshot.job_id != job.job_id
        || snapshot.operation_id != job.process.operation_id
        || snapshot.profile != job.invocation.profile
        || snapshot.invocation_target != job.invocation.target
        || snapshot.invocation_arguments != job.invocation.arguments
        || snapshot.source_root != job.target_roots.source_root
        || snapshot.target_root != job.target_roots.target_root
        || snapshot.cache_root != job.target_roots.cache_root
        || snapshot.metadata.instrument != NEXTTEST_INSTRUMENT
        || snapshot.metadata.profile != NEXTTEST_INSTRUMENT
        || snapshot.metadata.adapter != NEXTTEST_INSTRUMENT
        || snapshot.metadata.parser != NEXTTEST_INSTRUMENT
        || !snapshot.metadata.supports_test
    {
        return Err(TestdError::InvalidBinding);
    }
    for value in [
        snapshot.metadata.profile.as_str(),
        snapshot.metadata.profile_version.as_str(),
        snapshot.metadata.adapter.as_str(),
        snapshot.metadata.adapter_version.as_str(),
        snapshot.metadata.parser.as_str(),
        snapshot.metadata.normalizer.as_str(),
        snapshot.metadata.evaluator.as_str(),
        snapshot.metadata.verifier.as_str(),
        snapshot.original.parser_image_sha256.as_str(),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(TestdError::InvalidBinding);
        }
    }
    if !is_sha256(&snapshot.original.parser_image_sha256) {
        return Err(TestdError::InvalidBinding);
    }
    Ok(RetainedMetadata {
        profile: snapshot.metadata.profile,
        profile_version: snapshot.metadata.profile_version,
        adapter: snapshot.metadata.adapter,
        adapter_version: snapshot.metadata.adapter_version,
        parser: snapshot.metadata.parser,
        parser_image_sha256: snapshot.original.parser_image_sha256,
        normalizer: snapshot.metadata.normalizer,
        evaluator: snapshot.metadata.evaluator,
        verifier: snapshot.metadata.verifier,
    })
}

fn parse_retained_output(
    profile: &str,
    bytes: &[u8],
) -> Result<ParsedProviderOutput, eliot_instrument_nextest::NextestError> {
    if profile == TESTD_LIST_PROFILE {
        eliot_instrument_nextest::parse_list_json(bytes).map(|inventory| {
            ParsedProviderOutput::List {
                declared_count: inventory.declared_count,
                observed_count: inventory.tests.len() as u64,
            }
        })
    } else {
        eliot_instrument_nextest::parse_jsonl(bytes).map(|report| ParsedProviderOutput::Run {
            started: report.started,
            completed: report.completed,
            passed: report.passed,
            failed: report.failed,
            skipped: report.skipped,
            timed_out: report.timed_out,
            leaked: report.leaked,
            cancelled: report.cancelled,
        })
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN_EVENTS: &[u8] = br#"{"type":"test","event":"started","name":"package::works"}
{"type":"test","event":"ok","name":"package::works"}
"#;

    #[test]
    fn provider_evidence_uses_nextest_jsonl_parser_for_complete_run_stdout() {
        let parsed = parse_retained_output(TESTD_PRODUCTIVE_PROFILE, RUN_EVENTS);
        assert!(matches!(
            parsed,
            Ok(ParsedProviderOutput::Run {
                started: 1,
                completed: 1,
                passed: 1,
                ..
            })
        ));
    }

    #[test]
    fn provider_evidence_keeps_truncated_stdout_unparsed_and_malformed_output_failed() {
        let malformed = parse_retained_output(TESTD_PRODUCTIVE_PROFILE, b"{malformed\n");
        assert!(malformed.is_err());
        let truncated = RawArtifact::from_observation(
            "inline-stdout-0",
            RUN_CONTENT_TYPE,
            RUN_EVENTS.to_vec(),
            true,
            RawArtifactStream::Stdout,
            Default::default(),
        );
        assert!(matches!(
            truncated,
            Ok(artifact) if !is_parseable_stdout(&artifact, RUN_CONTENT_TYPE)
        ));
    }
}
