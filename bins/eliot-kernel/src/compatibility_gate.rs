//! I1.12 compatibility envelope on the process boundaries this Kernel binary
//! admits.
//!
//! One versioned handshake envelope, one durable compatibility state, one
//! verdict, so no Kernel-owned boundary can drift into a second spelling of the
//! comparison. This module owns the envelope for the boundaries this BINARY
//! admits: a replaceable Module generation on the front-door route
//! ([`super::frame_dispatch::runtime_module_compatibility`]), the store-bridge
//! seam ([`super::canonical_store_runtime`]), and the generation-cutover
//! candidate ([`super::generation_control::admit_cutover_candidate`]).
//!
//! Not every process handshake reaches this module, and saying where each one
//! IS gated is part of the claim rather than a caveat to it. The `eliotd`
//! process boundary is gated in the OTHER process, at `eliotd`'s own
//! `daemon_kernel_client::handshake::admit_kernel_peer_compatibility`, which
//! constructs no `CompatibilityEnvelope` and calls neither `admit_handshake`
//! nor this module. It compares the peer's presented values against values
//! THIS binary holds, using the owner admissions in `eliot_kernel_core`
//! (`admit_contract_set_digest`, `admit_canonical_format_range`,
//! `admit_architecture_source_digest`, `admit_normative_pair_receipt`,
//! `admit_migration_class`), and it REFUSES the absence of any of the five.
//!
//! Those five reach it because this binary publishes them into the daemon's
//! `ServerHello.config_snapshot` - a free-form JSON object - in a per-session
//! CLONE of the front-door policy, extended only when
//! `client.module_bridge_identity == ACTIVE_DAEMON_CALLER`. The clone is the
//! whole point and it is not incidental: `agent_bridge::begin_agent_bridge_inner`
//! computes a SHA-256 over the WHOLE stored policy object, and its receiver-held
//! half is built by installation-owned six-key literals
//! (`crates/kernel/eliot-installation/src/agent_bridge_profile.rs`,
//! `package_planner.rs`). Putting a key in the STORED object would change those
//! bytes for six binaries; extending a per-session copy leaves them identical.
//! The same asymmetry keeps the two closed decoders - `eliot-cli`'s
//! `KernelConfigSnapshot` (issue #1810) and `eliot-mod-research`'s
//! `ServerConfigSnapshot` (issue #24) - valid, because they bind other session
//! kinds and never see the daemon's extended copy.
//!
//! ## The Blob Store generation: a measured absence with a named owner
//!
//! #1968 names the Blob Store generation among the boundaries this Kernel
//! admits. Measured on this tree it is not a PROCESS handshake yet, so there is
//! no envelope to gate here, and none is fabricated from this module's own
//! constants - that would make every field a self-comparison:
//!
//! - There is no Blob Store process. `eliot-blob` and `eliot-blob-api` are
//!   library workspace members (`Cargo.toml:42-43`), no `eliot-blob` binary
//!   exists under `bins/`, and `BlobStoreService` is constructed only inside
//!   `crates/storage/eliot-blob`'s own tests. I1.2 and I05-02 keep the Blob
//!   Store co-located behind the store/daemon contract during D1, so a separate
//!   `eliot-blob.exe` generation is a measured extraction option rather than a
//!   D1 obligation; `workstreams/core-daemons/T3.md` records that decision
//!   under T3-B, owner issue #19.
//! - Nothing in production reaches the admission that does exist.
//!   `KernelComposition::demand_blob_store`
//!   (`bins/eliot-kernel/src/blob_store_controller.rs:566`) is called only from
//!   that binary's own tests, and `BlobStoreController::record_ready` compares
//!   only a caller-INJECTED probe generation string against the manifest's
//!   `approved_generation` - there is no peer operand for any other I1.12 item.
//! - No verdict could be durable for it: a blob generation is routed under no
//!   `RouteScope`, so [`persist_generation_compatibility`] has no key to write
//!   under and `generation_recovery::admit_generation_rollback` could not read
//!   one back.
//!
//! Gating that boundary is therefore work on the #19 extraction path: a real
//! process handshake, an owner-issued envelope, a durable route scope and a
//! production call site. This module records the absence instead of inventing
//! the missing pieces.
//!
//! The verdict this module admits travels with the candidate's generation and
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
//! The consequence is a named ceiling, not a claim: on a boundary this binary
//! admits, the ONLY outcome this gate can produce today is a construction
//! failure, reported as `envelope_version` when the envelope or the durable
//! state cannot be built at all. Every other field is the same value on both
//! sides, so it cannot disagree and cannot refuse.
//!
//! That includes the Authority Epoch, which is worth being exact about because
//! it looks like the one field a caller could get wrong:
//! [`admit_generation_activation`] builds the candidate envelope AND the durable
//! state from the SAME caller-supplied epoch, so the `authority_epoch` arm of
//! the comparison is structurally unreachable from here — it compares that one
//! value with itself. The epoch-lineage refusal that really happens on the
//! cutover path belongs to `generation_control::admit_cutover_candidate`, which
//! is a SEPARATE comparison it makes itself, against the live service epoch,
//! before this gate runs; it reports `authority_epoch` from its own check and
//! never reaches the arm above. A canonical-format, sealed normative-pair,
//! contract-set or migration-class incompatibility is likewise only observable
//! once a candidate presents
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
//! generation and epoch lineage, keyed by the ROUTE SCOPE the boundary is
//! routed under — [`super::frame_dispatch::RUNTIME_HEALTH_ROUTE_SCOPE`] on the
//! Module-generation seam, `super::STORE_BRIDGE_ROUTE` on the store-bridge seam
//! — NOT by the boundary's own module id, even though this function's parameter
//! is still named `module_id`.
//!
//! It must be the route scope, because the key half of the lookup is not
//! negotiable: `generation_recovery::admit_generation_rollback` iterates the
//! committed cutover records and calls itself with each record's own
//! `route_scope`, and the ORS read it performs is
//! `VersionedArtifactRegistry::compatibility`, a strict `(key, generation)`
//! lookup into `staged` and then `retained` with no fallback and no second
//! spelling. A module id is a DIFFERENT namespace from the route scope — the
//! front-door policy's module is `eliotd` while the route it is admitted under
//! is `daemon` — so recording under the module id writes a row no rollback gate
//! can ever find, and every restored `daemon` route is refused with "no recorded
//! compatibility verdict exists for this generation" no matter what the durable
//! state was. The artifact identity recorded beside it is still that
//! generation's own; only the lookup key is the route owner.
//!
//! `generation_recovery::admit_generation_rollback` re-reads exactly that record
//! and re-compares it with the compatibility state the Kernel runs under NOW. A
//! generation whose evidence was never recorded is refused as a rollback target,
//! and a recorded verdict stops being valid when the durable formats, digests,
//! migration class or epoch lineage drift after it was written — each with the
//! exact mismatching field. That is the "verified compatible with current state"
//! half of I1.12, and it is real on the restart path today.
//!
//! ## The one field whose two sides are not this build's own constants
//!
//! Every field above is either a constant of this build or the one value the
//! CALLER supplied, and it is that same value on both sides of the comparison,
//! so none of them can disagree with a peer. The Store API operation-manifest
//! catalogue digest is the single exception on this binary, and only on the
//! rollback half:
//! the store-bridge seam records the digest the store PROCESS presented onto the
//! evidence it persists, so the recorded half of that comparison is a peer
//! operand while the receiver-held half is
//! `eliot_kernel_service::kernel_store_api_contract_set_digest` — the catalogue
//! digest of the `eliot_store_api` compiled into THIS receiver. Neither side
//! receives its value from the other, and the recorded half is never this build's
//! own expectation.
//!
//! The receiver-held half is therefore bound on the rollback path and NOT here.
//! [`durable_compatibility_state`] is shared by every route, and handing a Store
//! API digest to a route that runs no store would make `admit_rollback` refuse
//! that route for recording no Store API claim at all. It is bound per route
//! scope, for the store-bridge route alone, by
//! `generation_recovery::store_bridge_durable_compatibility_state`. The
//! store-bridge seam's own live decision is untouched by that: a store which
//! presents no digest, or one this build's compiled `eliot_store_api` does not
//! produce, is still refused there before any durable write happens.

use eliot_contracts::{EpochId, ResourceGeneration};
use eliot_kernel_core::{
    CandidateActivation, CompatibilityEnvelope, CompatibilityMismatch, DurableCompatibilityState,
    MismatchField, NormativePairReceipt, StateMigrationClass, admit_candidate_activation,
    expected_seal_tag, handshake_canonical_format_range, handshake_protocol_range,
};
use eliot_ors::RedbRecoveryStore;

/// The durable compatibility state the Kernel is running under.
///
/// Built from the running binary's own protocol/format/contract/architecture
/// identity and one Authority Epoch, so every boundary and both the activation
/// and rollback gates are compared against ONE durable state rather than
/// several independently derived projections. Nothing here is invented and
/// nothing is carried over from a previous process.
///
/// The protocol range, canonical format range and contract-set digest are read
/// from their owners in `eliot-kernel-core` rather than restated here, so this
/// binary holds no second definition of any of them and a producer in another
/// binary presents the same values. The migration class is this binary's own
/// declaration, because I1.12 names the field without defining a vocabulary
/// this crate could own one from; see `StateMigrationClass`.
///
/// It deliberately carries NO Store API contract-set digest, because this is the
/// state of every route rather than of one boundary: a route that runs no store
/// records no Store API claim, so a receiver-held digest on such a route makes
/// `admit_rollback` refuse it. The receiver-held side of that one cross-build
/// comparison is bound where it can be scoped — on the rollback path, for the
/// store-bridge route scope alone; see the module documentation.
pub(crate) fn durable_compatibility_state(
    authority_epoch: &EpochId,
) -> Result<DurableCompatibilityState, String> {
    let protocol_range = handshake_protocol_range().map_err(|error| error.to_string())?;
    let canonical_format_range =
        handshake_canonical_format_range().map_err(|error| error.to_string())?;
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
/// identity rather than issued by the external normative-pair owner. The
/// envelope is therefore the shape and the single producer of the durable
/// evidence; it is NOT an independently declared claim about a different
/// artifact, so a peer can never disagree with it about these fields. See the
/// module documentation for what this does and does not prove.
pub(crate) fn process_compatibility_envelope(
    generation: ResourceGeneration,
    authority_epoch: &EpochId,
) -> Result<CompatibilityEnvelope, String> {
    let protocol_range = handshake_protocol_range().map_err(|error| error.to_string())?;
    let canonical_format_range =
        handshake_canonical_format_range().map_err(|error| error.to_string())?;
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
/// point of stating it. The candidate envelope and the durable state are both
/// derived from this build's own identity, and from the SAME caller-supplied
/// `authority_epoch` on both sides, so the only mismatch it can observe is its
/// own failure to build one of them — reported as `envelope_version` by
/// [`gate_construction_failure`]. The `authority_epoch` arm of the underlying
/// comparison is unreachable from this call for the same reason: it would
/// compare that one value with itself. A caller that wants an epoch-lineage
/// refusal makes that comparison itself against its own live epoch; on the
/// cutover path that caller is
/// [`super::generation_control::admit_cutover_candidate`].
///
/// It does NOT refuse an artifact whose protocol, contracts, canonical formats,
/// sealed normative-pair receipt or migration class differ from this build,
/// because nothing in this call is derived from the candidate artifact; such a
/// refusal requires a caller that presents an envelope issued by that artifact's
/// own owner.
///
/// `observed_at_ms` is the caller's observation clock; the decision itself reads
/// no clock, and the value is recorded only on a refusal.
pub(crate) fn admit_generation_activation(
    generation: ResourceGeneration,
    authority_epoch: &EpochId,
    observed_at_ms: i64,
) -> Result<CandidateActivation, CompatibilityMismatch> {
    let candidate = process_compatibility_envelope(generation, authority_epoch)
        .map_err(gate_construction_failure)?;
    let durable =
        durable_compatibility_state(authority_epoch).map_err(gate_construction_failure)?;
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
/// `module_id` is the LOOKUP KEY, and callers pass the ROUTE SCOPE the boundary
/// is routed under — [`super::frame_dispatch::RUNTIME_HEALTH_ROUTE_SCOPE`] or
/// `super::STORE_BRIDGE_ROUTE` — not a module id, despite the parameter name.
/// `generation_recovery::admit_generation_rollback` reads the row back under a
/// committed cutover record's `route_scope` through a strict
/// `(key, generation)` ORS lookup with no fallback, so a different namespace
/// here makes the verdict unreachable to the gate that consumes it. See the
/// module documentation.
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
