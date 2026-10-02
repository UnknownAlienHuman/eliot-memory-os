//! I1.12 compatibility envelope at every process boundary the Kernel owns.
//!
//! One versioned handshake envelope, one durable compatibility state, one
//! verdict. Kernel, the candidate `eliotd`, the store bridge, the Blob Store
//! generation and replaceable Module generations all reach their verdict
//! through this module, so no boundary can drift into a second spelling of the
//! comparison. The verdict it admits travels with the candidate's generation and
//! Authority Epoch lineage and is persisted in ORS, which is what makes a later
//! rollback re-verify recorded compatibility against current durable state
//! instead of trusting "it launched once" (I1.12).
//!
//! ## What this gate can refuse today, and what it cannot
//!
//! `admit_candidate_activation` compares the whole I1.12 field set and returns
//! the exact mismatching field, and that comparison is proven in its owner crate
//! (`eliot_kernel_core::compatibility_handshake`). On every production ingress in
//! this binary, however, BOTH sides of that comparison are built here, by the one
//! producer below, out of THIS build's own identity:
//! [`process_compatibility_envelope`] takes a generation and an epoch and fills
//! the protocol range, contract-set digest, canonical format range, Architecture
//! source digest, normative-pair seal, capabilities and migration class from this
//! crate's own constants and derivations, and [`durable_compatibility_state`]
//! fills the durable side from the same constants. A candidate envelope produced
//! that way cannot disagree with the durable state about any of those fields, and
//! the normative-pair seal tag is recomputed locally from this build's
//! normative pair rather than issued by the external owner, so nothing here is
//! evidence of an externally sealed receipt.
//!
//! The consequence is a named ceiling, not a claim: on a Kernel-owned boundary
//! this gate fails closed when the envelope cannot be built at all (reported as
//! `envelope_version`), and it refuses a candidate whose Authority Epoch the
//! CALLER supplied lies outside the live epoch lineage (reported as
//! `authority_epoch`; `generation_control::admit_cutover_candidate` compares the
//! candidate's epoch lineage against the live service epoch before this gate
//! runs). A canonical-format, sealed normative-pair, contract-set or
//! migration-class incompatibility is only observable once a candidate presents
//! an envelope issued by its own artifact owner — an owner-issued declaration
//! whose values are not derived from what it is compared against, carrying a
//! digest recomputed over its canonical bytes so a post-issuance edit is refused,
//! as the Claude I6.5 sidecar declaration does. No such owner issues one on any
//! current ingress, this module will not mint a candidate's envelope on its
//! behalf, and it does not invent a wire shape for a producer that does not
//! exist. Until one does, the per-field refusals are a property of the comparison
//! in the owner crate, not of this binary's boundaries.
//!
//! ## The half that IS enforced against durable state
//!
//! [`persist_generation_compatibility`] records the admitted evidence with its
//! generation and epoch lineage under the boundary's own module identity, and
//! `generation_recovery::admit_generation_rollback` re-reads exactly that record
//! and re-compares it with the compatibility state the Kernel runs under NOW. A
//! generation whose evidence was never recorded is refused as a rollback target,
//! and a recorded verdict stops being valid when the durable formats, digests,
//! migration class or epoch lineage drift after it was written — each with the
//! exact mismatching field. That is the "verified compatible with current state"
//! half of I1.12, and it is real on the restart path today.

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
/// Every field except the generation and the Authority Epoch comes from this
/// build's own identity, and the receipt's seal tag is recomputed here from that
/// identity rather than issued by the external normative-pair owner. The envelope
/// is therefore the shape and the single producer of the durable evidence; it is
/// NOT an independently declared claim about a different artifact, so a peer can
/// never disagree with it about these fields. See the module documentation for
/// what this does and does not prove.
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
/// a refusal carries the exact mismatching I1.12 field.
///
/// What this call can refuse is bounded by its arguments, and that bound is the
/// point of stating it: the candidate envelope and the durable state are both
/// derived from this build's own identity (see the module documentation), so the
/// fields that can disagree here are the envelope's own construction and the
/// Authority Epoch the caller passed in. It does NOT refuse an artifact whose
/// protocol, contracts, canonical formats, sealed normative-pair receipt or
/// migration class differ from this build, because nothing in this call is
/// derived from the candidate artifact; such a refusal requires a caller that
/// presents an envelope issued by that artifact's own owner.
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