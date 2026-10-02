//! I1.12 compatibility envelope at every process boundary the Kernel owns.
//!
//! One versioned handshake envelope, one durable compatibility state, one
//! verdict. Kernel, the candidate `eliotd`, the store bridge, the Blob Store
//! generation and replaceable Module generations all exchange the same
//! envelope and are gated by the same comparison, so "it can communicate" is
//! never enough to be accepted: the protocol range, the contract-set digest,
//! the canonical format range, the Architecture source digest with its
//! externally sealed `NormativePairIdentity` receipt, the module generation and
//! Authority Epoch, the required/optional capabilities and the state migration
//! class must all be compatible with current durable state.
//!
//! The accepted evidence is persisted with the candidate's generation and epoch
//! lineage, so "last known good" means verified compatible with current state
//! rather than "previously launched" (I1.12).

use eliot_contracts::{EpochId, ResourceGeneration};
use eliot_kernel_core::{
    CandidateActivation, CompatibilityEnvelope, CompatibilityMismatch, DurableCompatibilityState,
    MismatchField, NormativePairReceipt, StateMigrationClass, VersionRange,
    admit_candidate_activation, expected_seal_tag,
};
use eliot_ors::RedbRecoveryStore;

/// The I1.12 protocol revision this build speaks.
const HANDSHAKE_PROTOCOL_REVISION: u32 = 1;

/// The I1.12 canonical format revision this build speaks.
const HANDSHAKE_CANONICAL_FORMAT_REVISION: u32 = 1;

/// The durable compatibility state the Kernel is running under.
///
/// Built from the running binary's own protocol/format/contract/architecture
/// identity and one Authority Epoch, so every boundary and both the activation
/// and rollback gates are compared against ONE durable state rather than
/// several independently derived projections. Nothing here is invented and
/// nothing is carried over from a previous process.
pub(crate) fn durable_compatibility_state(
    authority_epoch: &EpochId,
) -> Result<DurableCompatibilityState, String> {
    let protocol_range =
        VersionRange::new(HANDSHAKE_PROTOCOL_REVISION, HANDSHAKE_PROTOCOL_REVISION)
            .map_err(|error| error.to_string())?;
    let canonical_format_range = VersionRange::new(
        HANDSHAKE_CANONICAL_FORMAT_REVISION,
        HANDSHAKE_CANONICAL_FORMAT_REVISION,
    )
    .map_err(|error| error.to_string())?;
    let contract_set_digest =
        super::frame_dispatch::runtime_contract_set_digest().map_err(|error| error.to_string())?;
    DurableCompatibilityState::new(
        protocol_range,
        contract_set_digest,
        canonical_format_range,
        eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST,
        authority_epoch.clone(),
        vec![super::frame_dispatch::RUNTIME_HEALTH_CAPABILITY.to_owned()],
        StateMigrationClass::NoMigration,
    )
    .map_err(|error| error.to_string())
}

/// The full versioned envelope one process boundary presents for a generation
/// and Authority Epoch.
///
/// The Architecture source digest is the current one and the receipt is sealed
/// for exactly that digest, so an envelope can only be admitted by a peer whose
/// durable state agrees on the digest AND on the externally issued seal tag.
pub(crate) fn process_compatibility_envelope(
    generation: ResourceGeneration,
    authority_epoch: &EpochId,
) -> Result<CompatibilityEnvelope, String> {
    let protocol_range =
        VersionRange::new(HANDSHAKE_PROTOCOL_REVISION, HANDSHAKE_PROTOCOL_REVISION)
            .map_err(|error| error.to_string())?;
    let canonical_format_range = VersionRange::new(
        HANDSHAKE_CANONICAL_FORMAT_REVISION,
        HANDSHAKE_CANONICAL_FORMAT_REVISION,
    )
    .map_err(|error| error.to_string())?;
    let contract_set_digest =
        super::frame_dispatch::runtime_contract_set_digest().map_err(|error| error.to_string())?;
    let architecture_source_digest = eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST;
    let normative_receipt = NormativePairReceipt::new(
        architecture_source_digest,
        expected_seal_tag(architecture_source_digest),
    )
    .map_err(|error| error.to_string())?;
    CompatibilityEnvelope::new(
        protocol_range,
        contract_set_digest,
        canonical_format_range,
        architecture_source_digest,
        normative_receipt,
        generation,
        authority_epoch.clone(),
        vec![super::frame_dispatch::RUNTIME_HEALTH_CAPABILITY.to_owned()],
        Vec::new(),
        StateMigrationClass::NoMigration,
    )
    .map_err(|error| error.to_string())
}

/// Gates one candidate generation for activation against current durable state.
///
/// The verdict is consulted BEFORE any registry, router or epoch state moves, and
/// a refusal carries the exact mismatching I1.12 field, so an artifact whose
/// protocol, contracts, canonical formats, sealed normative-pair receipt,
/// Authority Epoch or migration class is incompatible with current durable state
/// is refused before activation.
///
/// `observed_at_ms` is the caller's observation clock; the decision itself reads
/// no clock, and the value is recorded only on a refusal.
pub(crate) fn admit_generation_activation(
    generation: ResourceGeneration,
    authority_epoch: &EpochId,
    observed_at_ms: i64,
) -> Result<CandidateActivation, CompatibilityMismatch> {
    let candidate = process_compatibility_envelope(generation, authority_epoch)
        .map_err(|reason| gate_construction_failure(reason))?;
    let durable = durable_compatibility_state(authority_epoch).map_err(gate_construction_failure)?;
    admit_candidate_activation(&candidate, &durable, observed_at_ms)
        .map_err(|error| gate_construction_failure(error.to_string()))
}

/// Refusal for a boundary that could not even build the envelope it compares.
///
/// It is the envelope revision, because a peer that cannot present a
/// well-formed versioned envelope has not presented a handshake at this
/// revision at all.
fn gate_construction_failure(reason: String) -> CompatibilityMismatch {
    CompatibilityMismatch::new(MismatchField::EnvelopeVersion, reason)
}

/// Persists the accepted compatibility evidence with the candidate's own
/// generation and epoch lineage.
///
/// The ORS commit is the durable point: the versioned-artifact registry is the
/// only place the rollback gate reads a verdict from, so a candidate whose
/// evidence was never persisted can never become a rollback target. Staging the
/// recorded verdict is not an activation - it leaves the active executable
/// untouched, and `activate` remains the only route switch.
pub(crate) fn persist_generation_compatibility(
    ors: &RedbRecoveryStore,
    module_id: &str,
    artifact_hash: &str,
    activation: &CandidateActivation,
) -> Result<(), String> {
    let evidence = activation.require_admitted().map_err(|mismatch| {
        format!(
            "{} is incompatible with current durable state: {} ({})",
            module_id,
            mismatch.field(),
            mismatch.reason()
        )
    })?;
    let mut registry = ors
        .load_versioned_artifact_registry(eliot_ors::MAX_RECOVERY_PAGE)
        .map_err(|error| error.to_string())?;
    let generation = evidence.module_generation();
    let artifact = eliot_ors::VersionedArtifact::new(
        module_id,
        generation,
        artifact_hash,
        eliot_ors::VersionedArtifact::canonical_path(module_id, generation, artifact_hash),
    )
    .map_err(|error| error.to_string())?;
    registry
        .install_candidate(artifact, evidence.clone())
        .map_err(|error| error.to_string())?;
    ors.commit_versioned_artifact_registry(&registry)
        .map_err(|error| error.to_string())
}