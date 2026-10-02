//! Retained registry identity and deterministic dispatch composition for Testd.
//!
//! The generation below versions the first published ready provider dataset.
//! It is runner-owned metadata, independent of Kernel resource generations.

use std::collections::BTreeSet;

use eliot_bootstrap::normative::{
    NormativePairReceiptError, parse_normative_pair_receipt_with_key,
};
use eliot_instrument_api::InstrumentKind;
use eliot_testd_core::{
    RawArtifact, TestJob, TestdError, TestdSourceObservation, TestdToolObservation,
};
use serde::{Deserialize, Serialize};

use crate::{
    AvailabilityInputs, ProviderDispatch, ProviderRegistry, RegistryEntry, RegistryError,
    TestdDispatchError,
};

/// Owner revision of the published current ready-provider dataset.
///
/// W2 metadata: revision 1 names the first published READY provider dataset
/// and its six accepted shipped entries. This declaration versions owner
/// metadata; it is not an observed live catalog or a compatibility proof.
pub const READY_PROVIDER_REGISTRY_GENERATION: u64 = 1;
/// Snapshot artifact media type retained by the Testd store.
pub const TESTD_PROVIDER_REGISTRY_CONTENT_TYPE: &str =
    "application/vnd.eliot.provider-registry+json";
const SNAPSHOT_SCHEMA_VERSION: u16 = 1;
const NORMATIVE_PAIR_RECEIPT: &[u8] = include_bytes!("../../../../docs/normative-pair.toml");

/// Owner-observed values captured independently for the retained baseline and
/// the current dispatch check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestdProviderRegistryObservations {
    pub source: TestdSourceObservation,
    pub lock_sha256: String,
    pub toolchain: TestdToolObservation,
    pub environment_projection_sha256: String,
    pub profile_sha256: String,
    pub parser_image_sha256: String,
}

impl TestdProviderRegistryObservations {
    fn validate(&self) -> Result<(), TestdError> {
        self.source.validate()?;
        for (field, value) in [
            ("provider_registry.lock", self.lock_sha256.as_str()),
            (
                "provider_registry.environment",
                self.environment_projection_sha256.as_str(),
            ),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(TestdError::Invalid {
                    field,
                    reason: "must be non-blank and control-free",
                });
            }
        }
        self.toolchain.validate()?;
        for (field, digest) in [
            ("provider_registry.lock", self.lock_sha256.as_str()),
            (
                "provider_registry.environment",
                self.environment_projection_sha256.as_str(),
            ),
            ("provider_registry.profile", self.profile_sha256.as_str()),
            (
                "provider_registry.parser",
                self.parser_image_sha256.as_str(),
            ),
        ] {
            if !is_sha256(digest) {
                return Err(TestdError::Invalid {
                    field,
                    reason: "must be a lowercase SHA-256 digest",
                });
            }
        }
        Ok(())
    }

    /// Returns this owner's observations in the existing freshness shape.
    pub fn invalidation_set(&self) -> Result<crate::registry::InvalidationSet, TestdError> {
        let source = serde_json::to_string(&self.source)
            .map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let toolchain = serde_json::to_string(&self.toolchain)
            .map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let executable =
            serde_json::to_string(&(&self.toolchain.nextest_path, &self.toolchain.nextest_sha256))
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
        Ok(crate::registry::InvalidationSet {
            source,
            lock: self.lock_sha256.clone(),
            toolchain,
            env: self.environment_projection_sha256.clone(),
            exe: executable,
            profile: self.profile_sha256.clone(),
            parser: self.parser_image_sha256.clone(),
        })
    }
}

/// The exact static nextest mapping metadata which the retained dataset names.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdProviderRegistryMetadata {
    pub profile: String,
    pub profile_version: String,
    pub instrument: String,
    pub adapter: String,
    pub adapter_version: String,
    pub executable: Option<String>,
    pub executable_acquisition_rule: String,
    pub parser: String,
    pub normalizer: String,
    pub evaluator: String,
    pub verifier: String,
    pub environment_class: String,
    pub resource_contract: String,
    pub cancellation_contract: String,
    pub target_classes: BTreeSet<String>,
    pub supports_test: bool,
}

/// Immutable original values stored inside the content-validated raw artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdProviderRegistrySnapshot {
    schema_version: u16,
    pub registry_generation: u64,
    pub denominator_contract: String,
    pub denominator_contract_version: (u16, u16, u16),
    pub job_id: String,
    pub operation_id: String,
    pub profile: String,
    pub invocation_target: String,
    pub invocation_arguments: Vec<String>,
    pub source_root: String,
    pub target_root: String,
    pub cache_root: String,
    pub original: TestdProviderRegistryObservationsRecord,
    pub normative_pair_receipt: Vec<u8>,
    pub normative_architecture_sha256: String,
    pub normative_implementation_sha256: String,
    pub normative_pair_key: String,
    pub metadata: TestdProviderRegistryMetadata,
}

/// Serializable observation form retained as the original freshness baseline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdProviderRegistryObservationsRecord {
    pub source: TestdSourceObservation,
    pub lock_sha256: String,
    pub toolchain: TestdToolObservation,
    pub environment_projection_sha256: String,
    pub profile_sha256: String,
    pub parser_image_sha256: String,
}

impl From<&TestdProviderRegistryObservations> for TestdProviderRegistryObservationsRecord {
    fn from(value: &TestdProviderRegistryObservations) -> Self {
        Self {
            source: value.source.clone(),
            lock_sha256: value.lock_sha256.clone(),
            toolchain: value.toolchain.clone(),
            environment_projection_sha256: value.environment_projection_sha256.clone(),
            profile_sha256: value.profile_sha256.clone(),
            parser_image_sha256: value.parser_image_sha256.clone(),
        }
    }
}

impl TestdProviderRegistryObservationsRecord {
    fn observations(&self) -> TestdProviderRegistryObservations {
        TestdProviderRegistryObservations {
            source: self.source.clone(),
            lock_sha256: self.lock_sha256.clone(),
            toolchain: self.toolchain.clone(),
            environment_projection_sha256: self.environment_projection_sha256.clone(),
            profile_sha256: self.profile_sha256.clone(),
            parser_image_sha256: self.parser_image_sha256.clone(),
        }
    }
}

/// Creates and content-seals the first owner-observed snapshot for one job.
pub fn bind_testd_provider_registry_snapshot(
    job: &TestJob,
    observations: &TestdProviderRegistryObservations,
) -> Result<RawArtifact, TestdError> {
    observations.validate()?;
    let (pair, pair_key) = parse_normative_pair_receipt_with_key(NORMATIVE_PAIR_RECEIPT)
        .map_err(|error| normative_error(&error))?;
    let fingerprints = observations.invalidation_set()?;
    let registry = ProviderRegistry::ready_testd(
        READY_PROVIDER_REGISTRY_GENERATION,
        pair_key.clone(),
        &fingerprints,
    )
    .map_err(|error| registry_error(&error))?;
    let manifest = nextest_manifest(&registry)?;
    let snapshot = TestdProviderRegistrySnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        registry_generation: READY_PROVIDER_REGISTRY_GENERATION,
        denominator_contract: crate::DENOMINATOR_CONTRACT.to_owned(),
        denominator_contract_version: crate::DENOMINATOR_CONTRACT_VERSION,
        job_id: job.job_id.clone(),
        operation_id: job.process.operation_id.clone(),
        profile: job.invocation.profile.clone(),
        invocation_target: job.invocation.target.clone(),
        invocation_arguments: job.invocation.arguments.clone(),
        source_root: job.target_roots.source_root.clone(),
        target_root: job.target_roots.target_root.clone(),
        cache_root: job.target_roots.cache_root.clone(),
        original: TestdProviderRegistryObservationsRecord::from(observations),
        normative_pair_receipt: NORMATIVE_PAIR_RECEIPT.to_vec(),
        normative_architecture_sha256: pair.architecture_sha256,
        normative_implementation_sha256: pair.implementation_sha256,
        normative_pair_key: pair_key,
        metadata: manifest,
    };
    encode_testd_provider_registry_snapshot(&snapshot, &job.process.operation_id)
}

/// Serializes a registry snapshot into its exact immutable Testd artifact.
pub fn encode_testd_provider_registry_snapshot(
    snapshot: &TestdProviderRegistrySnapshot,
    operation_id: &str,
) -> Result<RawArtifact, TestdError> {
    let bytes =
        serde_json::to_vec(snapshot).map_err(|error| TestdError::Corrupt(error.to_string()))?;
    RawArtifact::from_bytes(
        format!("provider-registry:{operation_id}"),
        TESTD_PROVIDER_REGISTRY_CONTENT_TYPE,
        bytes,
        false,
    )
}

/// Validates the owning raw artifact before parsing and binds the record to job.
pub fn decode_testd_provider_registry_snapshot(
    artifact: &RawArtifact,
    job: &TestJob,
) -> Result<TestdProviderRegistrySnapshot, TestdError> {
    validate_snapshot_artifact(artifact, &job.process.operation_id)?;
    let snapshot: TestdProviderRegistrySnapshot = serde_json::from_slice(&artifact.bytes)
        .map_err(|error| TestdError::Corrupt(error.to_string()))?;
    validate_snapshot_for_job(&snapshot, job)?;
    let (pair, key) = parse_normative_pair_receipt_with_key(&snapshot.normative_pair_receipt)
        .map_err(|error| normative_error(&error))?;
    if pair.architecture_sha256 != snapshot.normative_architecture_sha256
        || pair.implementation_sha256 != snapshot.normative_implementation_sha256
        || key != snapshot.normative_pair_key
    {
        return Err(TestdError::InvalidBinding);
    }
    snapshot.original.observations().validate()?;
    Ok(snapshot)
}

fn validate_snapshot_artifact(
    artifact: &RawArtifact,
    operation_id: &str,
) -> Result<(), TestdError> {
    artifact.validate()?;
    if artifact.truncated
        || artifact.content_type != TESTD_PROVIDER_REGISTRY_CONTENT_TYPE
        || artifact.handle != format!("provider-registry:{operation_id}")
    {
        return Err(TestdError::InvalidBinding);
    }
    Ok(())
}

/// Reconstructs a dispatchable registry only from the immutable original.
pub fn build_testd_provider_registry(
    snapshot: &TestdProviderRegistrySnapshot,
) -> Result<ProviderRegistry, TestdError> {
    if snapshot.registry_generation != READY_PROVIDER_REGISTRY_GENERATION
        || snapshot.denominator_contract != crate::DENOMINATOR_CONTRACT
        || snapshot.denominator_contract_version != crate::DENOMINATOR_CONTRACT_VERSION
        || snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION
    {
        return Err(TestdError::InvalidBinding);
    }
    let original = snapshot.original.observations();
    original.validate()?;
    let fingerprints = snapshot.original_fingerprints()?;
    let registry = ProviderRegistry::ready_testd(
        snapshot.registry_generation,
        snapshot.normative_pair_key.clone(),
        &fingerprints,
    )
    .map_err(|error| registry_error(&error))?;
    let manifest = nextest_manifest(&registry)?;
    if manifest != snapshot.metadata {
        return Err(TestdError::InvalidBinding);
    }
    // The six accepted ready entries are the versioned dataset. Runtime tool,
    // executable and environment observations remain in the separate
    // invalidation set and sealed ProcessIntent; they never rewrite entry-owned
    // profile identity slots.
    Ok(registry)
}

/// Runs the existing Testd profile mapping and preserves its typed disposition.
pub fn compose_testd_provider_dispatch(
    registry: &ProviderRegistry,
    profile: &str,
    inputs: &AvailabilityInputs<'_>,
) -> Result<ProviderDispatch, TestdDispatchError> {
    crate::testd_profile_dispatch::compose_testd_profile_dispatch(registry, profile, inputs)
}

/// Validates the selected entry as the exact accepted adapter factory for one
/// closed Testd profile mapping before the runtime derives a productive intent.
pub fn validate_testd_provider_factory(
    registry: &ProviderRegistry,
    profile: &str,
    selected: &RegistryEntry,
) -> Result<String, TestdError> {
    let expected = crate::testd_profile_dispatch::instrument_contract_for_testd_profile(profile)
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    if selected.instrument.as_str() != expected
        || selected.profile.as_str() != expected
        || selected.adapter != expected
    {
        return Err(TestdError::InvalidBinding);
    }
    let (_, _, current_pair_key) = current_testd_normative_pair()?;
    if registry.generation() != READY_PROVIDER_REGISTRY_GENERATION
        || registry.normative_pair_digest() != current_pair_key.as_str()
    {
        return Err(TestdError::InvalidBinding);
    }
    let contract = eliot_contracts::ContractId::new(expected)
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    let registered = registry
        .resolve_parts(&contract, InstrumentKind::Test)
        .map_err(|error| registry_error(&error))?;
    let accepted = ProviderRegistry::ready_testd(
        READY_PROVIDER_REGISTRY_GENERATION,
        current_pair_key,
        &selected.invalidation,
    )
    .map_err(|error| registry_error(&error))?;
    let accepted_entry = accepted
        .resolve_parts(&contract, InstrumentKind::Test)
        .map_err(|error| registry_error(&error))?;
    if selected != registered
        || selected != accepted_entry
        || registry.len() != accepted.len()
        || !registry.iter().eq(accepted.iter())
    {
        return Err(TestdError::InvalidBinding);
    }
    selected
        .executable
        .executable
        .clone()
        .ok_or(TestdError::InvalidBinding)
}

impl TestdProviderRegistrySnapshot {
    /// Builds the currentness values carried by the retained registry snapshot.
    pub fn original_fingerprints(&self) -> Result<crate::registry::InvalidationSet, TestdError> {
        self.original.observations().invalidation_set()
    }
}

fn validate_snapshot_for_job(
    snapshot: &TestdProviderRegistrySnapshot,
    job: &TestJob,
) -> Result<(), TestdError> {
    validate_snapshot_owner(snapshot, &job.job_id, &job.process.operation_id)?;
    if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION
        || snapshot.registry_generation != READY_PROVIDER_REGISTRY_GENERATION
        || snapshot.denominator_contract != crate::DENOMINATOR_CONTRACT
        || snapshot.denominator_contract_version != crate::DENOMINATOR_CONTRACT_VERSION
        || snapshot.profile != job.invocation.profile
        || snapshot.invocation_target != job.invocation.target
        || snapshot.invocation_arguments != job.invocation.arguments
        || snapshot.source_root != job.target_roots.source_root
        || snapshot.target_root != job.target_roots.target_root
        || snapshot.cache_root != job.target_roots.cache_root
        || job.process.job_id != job.job_id
        || job.process.operation_id != job.invocation.request.request_id.as_str()
        || job.source_observation_before.as_ref() != Some(&snapshot.original.source)
    {
        return Err(TestdError::InvalidBinding);
    }
    Ok(())
}

fn validate_snapshot_owner(
    snapshot: &TestdProviderRegistrySnapshot,
    job_id: &str,
    operation_id: &str,
) -> Result<(), TestdError> {
    if snapshot.job_id != job_id || snapshot.operation_id != operation_id {
        return Err(TestdError::InvalidBinding);
    }
    Ok(())
}

fn nextest_manifest(
    registry: &ProviderRegistry,
) -> Result<TestdProviderRegistryMetadata, TestdError> {
    let entry = registry
        .iter()
        .find(|entry| entry.instrument.as_str() == eliot_instrument_nextest::NEXTEST_INSTRUMENT)
        .ok_or(TestdError::InvalidBinding)?;
    Ok(manifest_for_entry(entry))
}

fn manifest_for_entry(entry: &RegistryEntry) -> TestdProviderRegistryMetadata {
    TestdProviderRegistryMetadata {
        profile: entry.profile.as_str().to_owned(),
        profile_version: format!("{:?}", entry.profile_version),
        instrument: entry.instrument.as_str().to_owned(),
        adapter: entry.adapter.clone(),
        adapter_version: format!("{:?}", entry.adapter_version),
        executable: entry.executable.executable.clone(),
        executable_acquisition_rule: entry.executable.acquisition_rule.clone(),
        parser: entry.parser.as_str().to_owned(),
        normalizer: entry.normalizer.as_str().to_owned(),
        evaluator: entry.evaluator.as_str().to_owned(),
        verifier: entry.verifier.as_str().to_owned(),
        environment_class: entry.environment_class.clone(),
        resource_contract: entry.resource_contract.clone(),
        cancellation_contract: entry.cancellation_contract.clone(),
        target_classes: entry.targets.clone(),
        supports_test: entry.supports(InstrumentKind::Test),
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn normative_error(error: &NormativePairReceiptError) -> TestdError {
    TestdError::Contract(error.to_string())
}

fn registry_error(error: &RegistryError) -> TestdError {
    TestdError::Contract(error.to_string())
}

/// Current production normative bytes used for the independent freshness read.
pub fn current_testd_normative_pair() -> Result<(String, String, String), TestdError> {
    let (pair, key) = parse_normative_pair_receipt_with_key(NORMATIVE_PAIR_RECEIPT)
        .map_err(|error| normative_error(&error))?;
    Ok((pair.architecture_sha256, pair.implementation_sha256, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::StaleReason;
    use crate::{ProviderDispatch, ProviderDisposition};

    fn digest(byte: u8) -> String {
        std::iter::repeat_n(char::from(byte), 64).collect()
    }

    fn observations() -> Result<TestdProviderRegistryObservations, Box<dyn std::error::Error>> {
        let repository_root = std::env::current_dir()?;
        let executable_path = std::env::current_exe()?.to_string_lossy().into_owned();
        Ok(TestdProviderRegistryObservations {
            source: TestdSourceObservation {
                repository_root: repository_root.to_string_lossy().into_owned(),
                branch: "main".to_owned(),
                commit: "1".repeat(40),
                dirty_state_sha256: digest(b'a'),
            },
            lock_sha256: digest(b'b'),
            toolchain: eliot_testd_core::TestdToolObservation {
                nextest_path: std::env::current_exe()
                    .map(|path| path.to_string_lossy().into_owned())?,
                nextest_sha256: digest(b'd'),
                cargo_path: executable_path.clone(),
                cargo_sha256: digest(b'1'),
                rustc_path: executable_path,
                rustc_sha256: digest(b'2'),
                selected_toolchain: "selected-toolchain".to_owned(),
            },
            environment_projection_sha256: digest(b'c'),
            profile_sha256: digest(b'e'),
            parser_image_sha256: digest(b'f'),
        })
    }

    fn snapshot() -> Result<TestdProviderRegistrySnapshot, Box<dyn std::error::Error>> {
        let original = observations()?;
        let (pair, pair_key) = parse_normative_pair_receipt_with_key(NORMATIVE_PAIR_RECEIPT)?;
        let original_fingerprints = original.invalidation_set()?;
        let base = ProviderRegistry::ready_testd(
            READY_PROVIDER_REGISTRY_GENERATION,
            pair_key.clone(),
            &original_fingerprints,
        )?;
        Ok(TestdProviderRegistrySnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            registry_generation: READY_PROVIDER_REGISTRY_GENERATION,
            denominator_contract: crate::DENOMINATOR_CONTRACT.to_owned(),
            denominator_contract_version: crate::DENOMINATOR_CONTRACT_VERSION,
            job_id: "test-job".to_owned(),
            operation_id: "test-operation".to_owned(),
            profile: eliot_testd_core::TESTD_PRODUCTIVE_PROFILE.to_owned(),
            invocation_target: "workspace".to_owned(),
            invocation_arguments: vec!["--workspace".to_owned()],
            source_root: original.source.repository_root.clone(),
            target_root: "target".to_owned(),
            cache_root: "cache".to_owned(),
            original: TestdProviderRegistryObservationsRecord::from(&original),
            normative_pair_receipt: NORMATIVE_PAIR_RECEIPT.to_vec(),
            normative_architecture_sha256: pair.architecture_sha256,
            normative_implementation_sha256: pair.implementation_sha256,
            normative_pair_key: pair_key,
            metadata: nextest_manifest(&base)?,
        })
    }

    #[test]
    fn owner_observation_with_nextest_cargo_and_rustc_fields_validates()
    -> Result<(), Box<dyn std::error::Error>> {
        let observation = observations()?;
        observation.validate()?;
        let fingerprints = observation.invalidation_set()?;
        assert!(fingerprints.toolchain.contains("nextest_path"));
        assert!(fingerprints.toolchain.contains("cargo_path"));
        assert!(fingerprints.toolchain.contains("rustc_path"));
        assert!(!fingerprints.toolchain.chars().any(char::is_control));
        Ok(())
    }

    #[test]
    fn unchanged_registry_dispatches_all_independently_mapped_testd_profiles()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = snapshot()?;
        let original = snapshot.original.observations();
        let registry = build_testd_provider_registry(&snapshot)?;
        let fingerprints = original.invalidation_set()?;
        let inputs = AvailabilityInputs {
            generation: READY_PROVIDER_REGISTRY_GENERATION,
            normative_pair_digest: &snapshot.normative_pair_key,
            fingerprints: &fingerprints,
            platform: crate::host_platform(),
        };

        for profile in [
            eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
            eliot_testd_core::TESTD_LIST_PROFILE,
            eliot_testd_core::TESTD_SCOPED_PROFILE,
        ] {
            let dispatch = compose_testd_provider_dispatch(&registry, profile, &inputs)?;
            assert!(
                dispatch.is_dispatchable(),
                "{profile}: {:?}",
                dispatch.disposition()
            );
        }
        Ok(())
    }

    #[test]
    fn changed_source_lock_toolchain_environment_executable_profile_and_parser_refuse_stale()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = snapshot()?;
        let original = snapshot.original.observations();
        let registry = build_testd_provider_registry(&snapshot)?;
        let mutations: [fn(&mut TestdProviderRegistryObservations); 8] = [
            |value| value.source.branch.push_str("-changed"),
            |value| value.lock_sha256 = digest(b'0'),
            |value| value.toolchain.selected_toolchain.push_str("-changed"),
            |value| value.environment_projection_sha256 = digest(b'1'),
            |value| value.toolchain.nextest_path.push_str("-changed"),
            |value| value.toolchain.nextest_sha256 = digest(b'2'),
            |value| value.profile_sha256 = digest(b'3'),
            |value| value.parser_image_sha256 = digest(b'4'),
        ];

        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            let fingerprints = changed.invalidation_set()?;
            let inputs = AvailabilityInputs {
                generation: READY_PROVIDER_REGISTRY_GENERATION,
                normative_pair_digest: &snapshot.normative_pair_key,
                fingerprints: &fingerprints,
                platform: crate::host_platform(),
            };
            let dispatch = compose_testd_provider_dispatch(
                &registry,
                eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
                &inputs,
            )?;
            assert!(matches!(
                dispatch,
                ProviderDispatch::Refused {
                    disposition: ProviderDisposition::Stale {
                        reason: StaleReason::Fingerprint { .. }
                    }
                }
            ));
        }
        Ok(())
    }

    #[test]
    fn changed_normative_pair_refuses_with_its_typed_disposition()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = snapshot()?;
        let original = snapshot.original.observations();
        let fingerprints = original.invalidation_set()?;
        let registry = build_testd_provider_registry(&snapshot)?;
        let inputs = AvailabilityInputs {
            generation: READY_PROVIDER_REGISTRY_GENERATION,
            normative_pair_digest: "changed-normative-pair",
            fingerprints: &fingerprints,
            platform: crate::host_platform(),
        };
        let dispatch = compose_testd_provider_dispatch(
            &registry,
            eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
            &inputs,
        )?;
        assert!(matches!(
            dispatch,
            ProviderDispatch::Refused {
                disposition: ProviderDisposition::Stale {
                    reason: StaleReason::NormativePair
                }
            }
        ));
        Ok(())
    }

    #[test]
    fn changed_registry_generation_refuses_with_its_typed_disposition()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = snapshot()?;
        let original = snapshot.original.observations();
        let fingerprints = original.invalidation_set()?;
        let registry = build_testd_provider_registry(&snapshot)?;
        let inputs = AvailabilityInputs {
            generation: READY_PROVIDER_REGISTRY_GENERATION + 1,
            normative_pair_digest: &snapshot.normative_pair_key,
            fingerprints: &fingerprints,
            platform: crate::host_platform(),
        };
        let dispatch = compose_testd_provider_dispatch(
            &registry,
            eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
            &inputs,
        )?;
        assert!(matches!(
            dispatch,
            ProviderDispatch::Refused {
                disposition: ProviderDisposition::Stale {
                    reason: StaleReason::Generation { .. }
                }
            }
        ));
        Ok(())
    }

    #[test]
    fn selected_provider_factory_is_bound_to_the_closed_mapping_and_registry_entry()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = snapshot()?;
        let observations = snapshot.original.observations();
        let fingerprints = observations.invalidation_set()?;
        let registry = build_testd_provider_registry(&snapshot)?;
        let inputs = AvailabilityInputs {
            generation: READY_PROVIDER_REGISTRY_GENERATION,
            normative_pair_digest: &snapshot.normative_pair_key,
            fingerprints: &fingerprints,
            platform: crate::host_platform(),
        };
        let dispatch = compose_testd_provider_dispatch(
            &registry,
            eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
            &inputs,
        )?;
        let selected = dispatch
            .entry()
            .ok_or_else(|| std::io::Error::other("accepted mapping has no entry"))?;
        let program = validate_testd_provider_factory(
            &registry,
            eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
            selected,
        )?;
        assert_eq!(program, eliot_testd_core::TESTD_PRODUCTIVE_PROFILE_PROGRAM);

        let mut foreign = selected.clone();
        foreign.adapter.push_str("-foreign");
        assert!(
            validate_testd_provider_factory(
                &registry,
                eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
                &foreign,
            )
            .is_err()
        );
        // The ready static-description registry has a complete, internally
        // consistent cargo-wrapper entry; presenting that foreign factory to
        // the Testd-native registry must fail without rewriting its identities.
        let fingerprints = observations.invalidation_set()?;
        let static_description_registry = ProviderRegistry::ready(
            READY_PROVIDER_REGISTRY_GENERATION,
            snapshot.normative_pair_key.clone(),
            &fingerprints,
        )?;
        let foreign_executable = static_description_registry
            .resolve_parts(&selected.instrument, InstrumentKind::Test)?;
        assert!(
            validate_testd_provider_factory(
                &registry,
                eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
                foreign_executable,
            )
            .is_err()
        );
        assert!(
            validate_testd_provider_factory(&registry, "foreign-testd-profile", selected,).is_err()
        );
        Ok(())
    }

    #[test]
    fn snapshot_artifact_uses_the_operation_owned_raw_handle()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = snapshot()?;
        let artifact = encode_testd_provider_registry_snapshot(&snapshot, "test-operation")?;
        assert_eq!(artifact.handle, "provider-registry:test-operation");
        assert_eq!(artifact.content_type, TESTD_PROVIDER_REGISTRY_CONTENT_TYPE);
        assert!(!artifact.truncated);
        artifact.validate()?;
        assert!(validate_snapshot_artifact(&artifact, "foreign-operation").is_err());
        assert!(validate_snapshot_owner(&snapshot, "foreign-job", "test-operation").is_err());
        assert!(validate_snapshot_owner(&snapshot, "test-job", "foreign-operation").is_err());
        Ok(())
    }
}
