//! Capability-cell registry binding for the research provider (#24, W8).
//!
//! `ProviderAdmission` seals the Module/Capability Registry references the
//! Kernel admitted as #13's own `CapabilityCellId` and `RuntimeBundleId`
//! rather than as free text. This module is the other half of that binding: it
//! resolves the record this package's own manifest declared, out of the
//! generated registry, and returns #13's typed proof record so the caller can
//! receipt which compiled capability cell admitted the operation. Without it
//! the `CapabilityCellId` would be a well-formed string the process chose
//! rather than a catalogued capability.
//!
//! Ownership and direction:
//! - The generated block below is the compiled projection of
//!   `bins/eliot-mod-research/Cargo.toml::[package.metadata.eliot].functional_cell`
//!   and `bins/eliot-mod-research/capability-cell.contract.toml`. It is emitted
//!   by `scripts/gen_capability_cell_registry.py` and must not be hand-edited.
//! - The cell identity and the source package the resolution is keyed by are
//!   *also* generated, from the same one input chain. The expected pair is
//!   therefore an independent expected set read beside the record, never a
//!   copy of the registry's own roster: a registry cannot satisfy the lookup by
//!   listing itself.
//! - Resolution is [`CapabilityCellRegistry::resolve_cell_proof`], the #13
//!   owner primitive. This module restates no record-side check and adds no
//!   parallel cell schema, so the Kernel-side
//!   `bins/eliot-kernel/src/composition_bootstrap.rs` consumer and this one
//!   cannot drift apart.
//! - Nothing here mints authority, widens a record, or falls back: an absent,
//!   duplicate, stale, or unbound record is a typed refusal that the caller
//!   turns into `KERNEL_ADMISSION_REQUIRED`.
//!
//! The cell this package declares is `mod-research-provider`, the same identity
//! the Kernel's authenticated research dispatch presents as
//! `ResearchProviderDispatch::module_id`. The `mod-research-provider` literals
//! that already existed in this crate are test fixtures for the admission
//! constructor; this module adds the production constant and the readback the
//! sealed admission is actually bound through, not a second spelling.

// BEGIN GENERATED research-provider capability-cell registry (scripts/gen_capability_cell_registry.py; do not hand-edit)
const RESEARCH_PROVIDER_CAPABILITY_CELL_ID: &str = "mod-research-provider";
const RESEARCH_PROVIDER_CAPABILITY_SOURCE_PACKAGE: &str = "eliot-mod-research";
const RESEARCH_PROVIDER_CAPABILITY_CELL_REGISTRY_JSON: &str = r#"{"cells":[{"affected_edges":[],"allowed_effect_classes":[],"cell":"mod-research-provider","cell_revision":{"major":1,"minor":0,"patch":0},"contract_digest":"fd0a6fbf1af1d4463ea2ced41576c8b1abf5ef2cd74a79a3716067486558d731","contract_digest_source":"bins/eliot-mod-research/capability-cell.contract.toml#contract-surface","execution_contour":"HOST_INLINE","freshness":{"current_support":"CURRENT_UNVERIFIED","invalidation":[]},"generation_owner":"issue-24","lifecycle_owner":"issue-24","maintenance_owner":"issue-24","manifest":{"context_capsule":{"owner":"issue-24","present":true},"contract_kit":{"owner":"issue-24","present":true},"test_capsule":{"owner":"issue-24","present":true}},"product_pulse":{"NOT_APPLICABLE":{"reason":"This provider bridge process is candidate-only research acquisition: a completed provider run proves process custody and evidence lineage, not research correctness, coverage, or product behavior. Product evidence is measured at the Kernel research route and the installed operational spine (#11)."}},"proof_ceiling":"STATIC_FIELD_AND_MIGRATION_CONTRACT_ONLY","proof_entrypoint":"cargo test -p eliot-mod-research --all-targets --all-features","removal_boundary":"Stop admitting research-provider dispatches, drain and cancel the exact eliot-mod-research process generation through Kernel, then remove the provider bridge; the Kernel research route answers CAPABILITY_UNAVAILABLE once the admitted material is no longer delivered.","replacement_class":"keep","runtime_bundle":null,"semantic_owner":"issue-24","source_crate":"eliot-mod-research","state_owners":[{"owner":"issue-24","state":"Per-operation admitted research-provider lifecycle: sealed admission, submitted envelope, raw provider evidence, provider job reference, terminal outcome, and cancellation receipt (in-process, per operation; no durable research Job/Attempt or coverage-denominator state)"}],"stateless":false}],"generator_version":"1.0.0","pair_key":"sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1","registry_version":1,"source_identity":{"cargo_lock_digest":"fc31e3176125cb717e6d665772d3181e11f7e11d64b3c47215402346b94863aa","generator_version":"1.0.0","toolchain":"rustc 1.97.1 (8bab26f4f 2026-07-14); binary: rustc; commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452; commit-date: 2026-07-14; host: x86_64-pc-windows-msvc; release: 1.97.1; LLVM version: 22.1.6","tree_digest":"79098f85d8b75a546d936e8ddbe202bcbe1c82ca4badcbb1c7f33b57351e131d"}}"#;
// END GENERATED research-provider capability-cell registry

use std::sync::OnceLock;

use eliot_contracts::{
    CapabilityCellId, CapabilityCellProof, CapabilityCellProofError, CapabilityCellRegistry,
    SourceCrateRef,
};

use crate::admission::{AdmissionRefusal, ProviderAdmission};

/// The generated registry, typed-decoded at most once per process.
///
/// The registry is held **by value** here rather than as a borrow taken from the
/// closure that decodes it, so no borrow of `registry.cells` can outlive the
/// registry it points into. This is the same shape as
/// `bins/eliot-kernel/src/composition_bootstrap.rs::NATIVE_WORKER_CELL_REGISTRY`,
/// which also keeps its `CapabilityCellRegistry` by value in a `OnceLock`.
static RESEARCH_PROVIDER_CELL: OnceLock<Result<CapabilityCellRegistry, String>> = OnceLock::new();

/// Binds the admission's sealed capability cell to the generated #13 record and
/// returns that record's typed proof surface.
///
/// The lookup is keyed by the admission's own sealed [`CapabilityCellId`], so a
/// Kernel that admitted some other module id is refused rather than resolved
/// against this package's cell; and the resolution itself is #13's
/// [`CapabilityCellRegistry::resolve_cell_proof`], which re-validates the whole
/// registry, refuses a duplicated cell, requires the single record to name this
/// compiled package, and requires a current independently invokable proof
/// entrypoint. A registry that merely *contains* a cell with this name is not
/// sufficient, and none of those comparisons can be satisfied by existence
/// alone.
///
/// The admitted Module generation is deliberately **not** matched here.
/// `CapabilityCellRecord::runtime_bundle` names a delegated runtime bundle and
/// this cell declares none: it executes inline in this process
/// (`HOST_INLINE`). `ProviderAdmission::module_generation_id` is the Module
/// generation the Kernel admitted, which is a different namespace from a
/// runtime bundle, and reading one as the other would be a fabricated
/// delegation claim. The generation reference stays sealed and #13-typed on the
/// admission.
///
/// # Errors
///
/// Returns [`AdmissionRefusal::UndeclaredCapabilityCell`] when the generated
/// registry cannot be typed-decoded, when the generated cell or package identity
/// is not a well-formed #13 reference, or when #13's resolution refuses it as
/// undeclared, ambiguous, owned by another source crate, or itself invalid;
/// [`AdmissionRefusal::CapabilityCellMismatch`] when the admission's sealed cell
/// id is not the declared cell; and
/// [`AdmissionRefusal::CapabilityCellUnsupported`] when the declared record
/// carries no independently invokable proof entrypoint or its current support is
/// stale, suspended, or invalidated. There is no default cell, no crate-name
/// match, and no partial acceptance.
pub fn resolve_admitted_cell(
    admission: &ProviderAdmission,
) -> Result<CapabilityCellProof, AdmissionRefusal> {
    let registry = match RESEARCH_PROVIDER_CELL.get_or_init(|| {
        serde_json::from_str(RESEARCH_PROVIDER_CAPABILITY_CELL_REGISTRY_JSON)
            .map_err(|_| "embedded research-provider cell registry is not decodable".to_owned())
    }) {
        Ok(registry) => registry,
        Err(_) => return Err(AdmissionRefusal::UndeclaredCapabilityCell),
    };
    // The expected cell and package identity are generated from the same input
    // chain as the record and are read as typed #13 references, so the lookup is
    // keyed by an independently generated expected set rather than by anything
    // taken out of the registry it is about to resolve.
    let expected_cell = CapabilityCellId::new(RESEARCH_PROVIDER_CAPABILITY_CELL_ID)
        .map_err(|_| AdmissionRefusal::UndeclaredCapabilityCell)?;
    let expected_source_crate = SourceCrateRef::new(RESEARCH_PROVIDER_CAPABILITY_SOURCE_PACKAGE)
        .map_err(|_| AdmissionRefusal::UndeclaredCapabilityCell)?;
    // The admitted Module/Capability Registry reference must name the exact
    // declared cell. `ProviderAdmission` already shape-checked it through
    // `CapabilityCellId::new`; this is the record-side binding, so a Kernel that
    // admitted some other module id cannot be silently treated as this cell.
    if admission.module_id().as_str() != expected_cell.as_str() {
        return Err(AdmissionRefusal::CapabilityCellMismatch);
    }
    let proof = registry
        .resolve_cell_proof(&expected_cell, &expected_source_crate)
        .map_err(|error| match error {
            CapabilityCellProofError::MissingProofEntrypoint
            | CapabilityCellProofError::StaleProofSurface => {
                AdmissionRefusal::CapabilityCellUnsupported
            }
            CapabilityCellProofError::UndeclaredCell { .. }
            | CapabilityCellProofError::AmbiguousCell { .. }
            | CapabilityCellProofError::SourceCrateMismatch { .. }
            | CapabilityCellProofError::InvalidRegistry => {
                AdmissionRefusal::UndeclaredCapabilityCell
            }
        })?;
    // The proof the owner returned is for the presented cell by construction;
    // re-reading it here is what keeps the returned record and the sealed
    // admission from describing different cells.
    if proof.cell().as_str() != admission.module_id().as_str() {
        return Err(AdmissionRefusal::CapabilityCellMismatch);
    }
    Ok(proof)
}