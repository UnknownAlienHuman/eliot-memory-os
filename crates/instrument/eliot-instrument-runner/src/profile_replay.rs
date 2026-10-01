//! Parser replay over owner-verified immutable Testd stream bytes.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ClockReading, StateFence, sha256_hex};
use eliot_instrument_api::{EvidenceCoverage, RawEvidence, RawEvidenceSource, VerificationOutcome};
use eliot_process::{ExitDisposition, ExitStatus};
use eliot_instrument_nextest::{
    NEXTEST_INSTRUMENT, NEXTEST_STDOUT_CONTENT_TYPE, parse_jsonl, parse_list_json,
};
use eliot_instrument_cargo::{CONTRACT_NAME as CARGO_INSTRUMENT, parse_jsonl as parse_cargo_jsonl};
use eliot_instrument_rustc::{RUSTC_INSTRUMENT, parse_clippy_jsonl};
use eliot_instrument_rustfmt::{RUSTFMT_INSTRUMENT, parse_output as parse_rustfmt_output};
use eliot_testd_core::{
    EphemeralSourceBytes, InstrumentStageRequest, StageExecutionKind, TESTD_LIST_PROFILE,
    TestdEvaluationObservation, TestdEvaluationStatus, TestdParsingObservation, TestdParsingStatus,
    TestdProviderCatalogLifecycle, TestdStreamDisposition, TestdStreamEvidenceBinding,
};
use thiserror::Error;

use crate::{
    profile::{InstrumentRegistry, ProfileCompiler},
    registry::{InvalidationSet, ProviderRegistry, RegistryEntry, RegistryError, RegistryFreshness},
};

/// Kernel/owner-issued replay context bound to one exact accepted catalog row
/// and one independently observed provider fingerprint set.
///
/// The context is deliberately not constructible from a Testd material
/// projection. Callers mint it from a current `ModuleCatalogOwnerReadback`,
/// the corresponding accepted `GenerationAdmission`, and current fingerprint
/// observations, then retain the required profile/provider IDs separately
/// from the stage projection.
#[derive(Clone, Debug)]
pub struct VerifiedTestdReplayContext {
    profile_registry: InstrumentRegistry,
    provider_registry: ProviderRegistry,
    fingerprints: InvalidationSet,
    required_profile_ids: BTreeSet<String>,
    required_provider_ids: BTreeSet<(String, String)>,
    required_test_ids: BTreeSet<String>,
}

impl VerifiedTestdReplayContext {
    /// Issues a replay context only after the exact current catalog readback
    /// revalidates its accepted module generation. `required_provider_ids`
    /// are `(instrument, adapter)` identities selected independently by the
    /// caller; they are not derived from Testd's stage material.
    pub fn from_owner_readback(
        profile_registry: InstrumentRegistry,
        readback: &eliot_module_registry::ModuleCatalogOwnerReadback,
        expected_owner_revision: u64,
        expected_catalog_revision: u64,
        expected_state_fence: &StateFence,
        admission: &eliot_module_registry::GenerationAdmission,
        normative_pair_digest: String,
        fingerprints: InvalidationSet,
        required_profile_ids: BTreeSet<String>,
        required_provider_ids: BTreeSet<(String, String)>,
        required_test_ids: BTreeSet<String>,
    ) -> Result<Self, ProfileReplayError> {
        let lifecycle = readback.verify_generation_admission(
            expected_owner_revision,
            expected_catalog_revision,
            expected_state_fence,
            admission,
        )?;
        if required_profile_ids.is_empty() {
            return Err(ProfileReplayError::EmptyRequiredProfiles);
        }
        if required_provider_ids.is_empty() {
            return Err(ProfileReplayError::EmptyRequiredProviders);
        }
        let provider_registry = ProviderRegistry::ready_for_catalog_generation(
            lifecycle,
            normative_pair_digest,
            &fingerprints,
        )?;
        Ok(Self {
            profile_registry,
            provider_registry,
            fingerprints,
            required_profile_ids,
            required_provider_ids,
            required_test_ids,
        })
    }

    /// Replays bytes already read back from the owner through the context's
    /// exact current registries and independently retained required IDs.
    #[allow(clippy::too_many_arguments)]
    pub fn replay_stream(
        &self,
        stage: &InstrumentStageRequest,
        source: &TestdStreamEvidenceBinding,
        bytes: &EphemeralSourceBytes,
        terminal: Option<&ExitStatus>,
        started_at: ClockReading,
        finished_at: ClockReading,
    ) -> Result<ProfileReplayReceipt, ProfileReplayError> {
        let provider_freshness = RegistryFreshness {
            generation: self.provider_registry.generation(),
            normative_pair_digest: self.provider_registry.normative_pair_digest(),
            fingerprints: &self.fingerprints,
        };
        replay_profile_stream_admitted(
            &self.profile_registry,
            &self.provider_registry,
            &provider_freshness,
            stage,
            source,
            bytes,
            &self.required_profile_ids,
            &self.required_provider_ids,
            &self.required_test_ids,
            terminal,
            started_at,
            finished_at,
        )
    }
}

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
    /// Exact catalog readback failed its owner-revision/admission checks.
    #[error(transparent)]
    Catalog(#[from] eliot_module_registry::ModuleRegistryAdmissionError),
    /// Production replay context omitted its independently retained profile set.
    #[error("replay context has no required profile IDs")]
    EmptyRequiredProfiles,
    /// Production replay context omitted its independently retained provider set.
    #[error("replay context has no required provider IDs")]
    EmptyRequiredProviders,
    /// Stage profile is outside the independently retained required profile set.
    #[error("retained profile is not in the required profile set")]
    UnrequiredProfile,
    /// Resolved provider is outside the independently retained provider set.
    #[error("resolved provider is not in the required provider set")]
    UnrequiredProvider,
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
    replay_profile_stream_inner(
        profile_registry,
        provider_registry,
        freshness,
        stage,
        source,
        bytes,
        None,
        None,
        required_test_ids,
        None,
        started_at,
        finished_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn replay_profile_stream_admitted(
    profile_registry: &InstrumentRegistry,
    provider_registry: &ProviderRegistry,
    freshness: &RegistryFreshness<'_>,
    stage: &InstrumentStageRequest,
    source: &TestdStreamEvidenceBinding,
    bytes: &EphemeralSourceBytes,
    required_profile_ids: &BTreeSet<String>,
    required_provider_ids: &BTreeSet<(String, String)>,
    required_test_ids: &BTreeSet<String>,
    terminal: Option<&ExitStatus>,
    started_at: ClockReading,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    replay_profile_stream_inner(
        profile_registry,
        provider_registry,
        freshness,
        stage,
        source,
        bytes,
        Some(required_profile_ids),
        Some(required_provider_ids),
        required_test_ids,
        Some(terminal),
        started_at,
        finished_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn replay_profile_stream_inner(
    profile_registry: &InstrumentRegistry,
    provider_registry: &ProviderRegistry,
    freshness: &RegistryFreshness<'_>,
    stage: &InstrumentStageRequest,
    source: &TestdStreamEvidenceBinding,
    bytes: &EphemeralSourceBytes,
    required_profile_ids: Option<&BTreeSet<String>>,
    required_provider_ids: Option<&BTreeSet<(String, String)>>,
    required_test_ids: &BTreeSet<String>,
    terminal: Option<&ExitStatus>,
    started_at: ClockReading,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    stage
        .validate()
        .map_err(|error| ProfileReplayError::InvalidStage {
            detail: error.to_string(),
        })?;
    let (entry, parser_revision) = current_selection(profile_registry, provider_registry, freshness, stage)?;
    if required_profile_ids.is_some_and(|required| !required.contains(&stage.profile_name)) {
        return Err(ProfileReplayError::UnrequiredProfile);
    }
    if required_provider_ids.is_some_and(|required| {
        !required.contains(&(entry.instrument.as_str().to_owned(), entry.adapter.clone()))
    }) {
        return Err(ProfileReplayError::UnrequiredProvider);
    }
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
    if stage.stage_id == "nextest-list" && entry.instrument.as_str() == NEXTEST_INSTRUMENT {
        return list_receipt(source, verified, bytes, entry, parser_revision, finished_at);
    }
    match entry.instrument.as_str() {
        CARGO_INSTRUMENT if stage.stage_id == "cargo-metadata" => {
            cargo_metadata_receipt(source, verified, bytes, entry, parser_revision, terminal, finished_at)
        }
        CARGO_INSTRUMENT => cargo_receipt(source, verified, bytes, entry, parser_revision, terminal, finished_at),
        RUSTC_INSTRUMENT => rustc_receipt(source, verified, bytes, entry, parser_revision, terminal, finished_at),
        RUSTFMT_INSTRUMENT => rustfmt_receipt(source, verified, bytes, entry, parser_revision, terminal, finished_at),
        NEXTEST_INSTRUMENT => run_receipt(
            source,
            verified,
            bytes,
            stage,
            entry,
            parser_revision,
            required_test_ids,
            terminal,
            started_at,
            finished_at,
        ),
        _ => Err(ProfileReplayError::UnsupportedProfile { profile: stage.profile_name.clone() }),
    }
}

fn current_selection<'a>(
    profile_registry: &InstrumentRegistry,
    provider_registry: &'a ProviderRegistry,
    freshness: &RegistryFreshness<'_>,
    stage: &InstrumentStageRequest,
) -> Result<(&'a RegistryEntry, String), ProfileReplayError> {
    let lifecycle =
        provider_registry
            .lifecycle_binding()
            .ok_or(ProfileReplayError::StageMismatch {
                field: "provider_catalog_lifecycle",
            })?;
    if lifecycle.provider_registry_generation() != provider_registry.generation() {
        return Err(ProfileReplayError::StageMismatch {
            field: "provider_catalog_generation",
        });
    }
    let retained_lifecycle =
        stage
            .provider_catalog_lifecycle
            .as_ref()
            .ok_or(ProfileReplayError::StageMismatch {
                field: "provider_catalog_lifecycle",
            })?;
    if !lifecycle_matches(retained_lifecycle, lifecycle) {
        return Err(ProfileReplayError::StageMismatch {
            field: "provider_catalog_lifecycle",
        });
    }
    if retained_lifecycle.state_fence != stage.invocation.request.state_fence {
        return Err(ProfileReplayError::StageMismatch {
            field: "provider_catalog_state_fence",
        });
    }
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
    let retained_command = stage
        .stage_command
        .as_ref()
        .ok_or(ProfileReplayError::StageMismatch { field: "stage_command" })?;
    if retained_command.executable != selected.command.executable
        || retained_command.argv != selected.command.argv
        || retained_command.spec_digest != selected.spec_digest
    {
        return Err(ProfileReplayError::StageMismatch { field: "stage_command" });
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
    let supported_process = match entry.instrument.as_str() {
        CARGO_INSTRUMENT => matches!(stage.kind, eliot_instrument_api::InstrumentKind::Build | eliot_instrument_api::InstrumentKind::Test),
        RUSTC_INSTRUMENT => stage.kind == eliot_instrument_api::InstrumentKind::Build,
        RUSTFMT_INSTRUMENT => stage.kind == eliot_instrument_api::InstrumentKind::Format,
        NEXTEST_INSTRUMENT => stage.kind == eliot_instrument_api::InstrumentKind::Test,
        _ => false,
    };
    if stage.execution != StageExecutionKind::Process || !supported_process {
        return Err(ProfileReplayError::UnsupportedProfile {
            profile: stage.profile_name.clone(),
        });
    }
    Ok((entry, format!("generation:{}", selected.parser_generation)))
}

fn lifecycle_matches(
    retained: &TestdProviderCatalogLifecycle,
    current: &eliot_module_registry::VerifiedModuleCatalogGeneration,
) -> bool {
    retained.owner_revision == current.owner_revision()
        && retained.catalog_revision == current.catalog_revision()
        && retained.catalog_digest == current.catalog_digest()
        && retained.state_fence == *current.state_fence()
        && retained.module_id == current.module_id().as_str()
        && retained.generation_id == current.generation_id().as_str()
        && retained.artifact_digest == current.artifact_digest()
        && retained.config_digest == current.config_digest()
        && retained.protocol_digest == current.protocol_digest()
        && retained.manifest_digest == current.manifest_digest()
        && retained.admission_receipt == current.admission_receipt()
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

fn cargo_receipt(
    source: &TestdStreamEvidenceBinding,
    verified: VerifiedSource<'_>,
    bytes: &EphemeralSourceBytes,
    entry: &RegistryEntry,
    parser_revision: String,
    terminal: Option<&ExitStatus>,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    let report = match parse_cargo_jsonl(bytes.bytes()) {
        Ok(report) => report,
        Err(error) => return parse_failed_receipt(source, verified, entry, parser_revision, error.to_string(), finished_at),
    };
    // Cargo's build-finished record and error diagnostics are its evaluator
    // contract. Missing build-finished remains Unknown.
    let outcome = terminal_outcome(report.outcome(), terminal);
    evaluated_report_receipt(
        source,
        verified,
        entry,
        parser_revision,
        outcome,
        "cargo-json-message-outcome",
        finished_at,
    )
}

fn cargo_metadata_receipt(
    source: &TestdStreamEvidenceBinding,
    verified: VerifiedSource<'_>,
    bytes: &EphemeralSourceBytes,
    entry: &RegistryEntry,
    parser_revision: String,
    terminal: Option<&ExitStatus>,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    if let Err(error) = eliot_instrument_cargo::parse_metadata_json(bytes.bytes()) {
        return parse_failed_receipt(source, verified, entry, parser_revision, error.to_string(), finished_at);
    }
    evaluated_report_receipt(
        source,
        verified,
        entry,
        parser_revision,
        terminal_outcome(VerificationOutcome::Pass, terminal),
        "cargo-metadata-workspace-denominator-and-terminal-outcome",
        finished_at,
    )
}

fn rustc_receipt(
    source: &TestdStreamEvidenceBinding,
    verified: VerifiedSource<'_>,
    bytes: &EphemeralSourceBytes,
    entry: &RegistryEntry,
    parser_revision: String,
    terminal: Option<&ExitStatus>,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    let report = match parse_clippy_jsonl(bytes.bytes()) {
        Ok(report) => report,
        Err(error) => return parse_failed_receipt(source, verified, entry, parser_revision, error.to_string(), finished_at),
    };
    // Clippy's JSON has no terminal-success record. Diagnostics can prove a
    // compiler error; absence of errors alone cannot prove a successful exit.
    let outcome = terminal_outcome(report.outcome(), terminal);
    evaluated_report_receipt(
        source,
        verified,
        entry,
        parser_revision,
        outcome,
        "clippy-json-diagnostic-outcome",
        finished_at,
    )
}

fn rustfmt_receipt(
    source: &TestdStreamEvidenceBinding,
    verified: VerifiedSource<'_>,
    bytes: &EphemeralSourceBytes,
    entry: &RegistryEntry,
    parser_revision: String,
    terminal: Option<&ExitStatus>,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    match parse_rustfmt_output(bytes.bytes()) {
        Ok(report) => evaluated_report_receipt(
            source,
            verified,
            entry,
            parser_revision,
            // Rustfmt needs the exact process exit from the ProcessExecutor
            // observation; a missing or nonterminal status remains Unknown.
            report.outcome(terminal_code(terminal), terminal_cancelled(terminal)),
            "rustfmt-output-and-terminal-outcome",
            finished_at,
        ),
        Err(error) => parse_failed_receipt(source, verified, entry, parser_revision, error.to_string(), finished_at),
    }
}

fn terminal_code(terminal: Option<&ExitStatus>) -> Option<i32> {
    terminal
        .filter(|status| status.disposition() == ExitDisposition::Completed)
        .and_then(ExitStatus::code)
}

fn terminal_cancelled(terminal: Option<&ExitStatus>) -> bool {
    terminal.is_some_and(|status| status.disposition() == ExitDisposition::Cancelled)
}

fn terminal_outcome(parsed: VerificationOutcome, terminal: Option<&ExitStatus>) -> VerificationOutcome {
    match terminal.map(ExitStatus::disposition) {
        Some(ExitDisposition::Completed) if terminal_code(terminal) == Some(0) => parsed,
        Some(ExitDisposition::Completed) => VerificationOutcome::Fail,
        Some(ExitDisposition::Cancelled) => VerificationOutcome::Cancelled,
        Some(ExitDisposition::Signalled | ExitDisposition::ResourceLimit | ExitDisposition::Unknown)
        | None => match parsed {
            VerificationOutcome::Fail => VerificationOutcome::Fail,
            _ => VerificationOutcome::Unknown,
        },
    }
}

fn parse_failed_receipt(
    source: &TestdStreamEvidenceBinding,
    verified: VerifiedSource<'_>,
    entry: &RegistryEntry,
    parser_revision: String,
    detail: String,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    let parsing = parsing_observation(
        source,
        verified.readback_receipt_id,
        entry,
        parser_revision,
        TestdParsingStatus::ParseFailed,
        finished_at,
    )?;
    Ok(receipt_base(source, verified, Some(parsing), None, None, None, Some(detail)))
}

fn evaluated_report_receipt(
    source: &TestdStreamEvidenceBinding,
    verified: VerifiedSource<'_>,
    entry: &RegistryEntry,
    parser_revision: String,
    outcome: VerificationOutcome,
    evaluator_scope: &str,
    finished_at: ClockReading,
) -> Result<ProfileReplayReceipt, ProfileReplayError> {
    let parsing = parsing_observation(
        source,
        verified.readback_receipt_id,
        entry,
        parser_revision.clone(),
        TestdParsingStatus::Parsed,
        finished_at,
    )?;
    let evaluation_status = match outcome {
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
        evaluator_scope,
        source.evidence_identity_sha256.clone(),
        entry.parser.to_string(),
        parser_revision,
        verified.digest,
        false,
        verified.fence.clone(),
        finished_at,
    )
    .map_err(|error| ProfileReplayError::Evaluator { detail: error.to_string() })?;
    Ok(receipt_base(
        source,
        verified,
        Some(parsing),
        Some(evaluation),
        Some(outcome),
        None,
        None,
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
    terminal: Option<&ExitStatus>,
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
            terminal,
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
    terminal: Option<&ExitStatus>,
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
    let outcome = terminal_outcome(run.outcome, terminal);
    let evaluation_status = match outcome {
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
        Some(outcome),
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
