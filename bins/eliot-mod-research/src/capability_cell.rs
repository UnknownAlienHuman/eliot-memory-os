//! Capability-cell registry binding for the research provider (#24, W8).
//!
//! `ProviderAdmission` seals the Module/Capability Registry references the
//! Kernel admitted as #13's own `CapabilityCellId` and `RuntimeBundleId`
//! rather than as free text. This module is the other half of that binding: it
//! reads the record this package's own manifest declared, out of the generated
//! registry, and proves that the sealed cell identity actually names a declared
//! cell with a current, independently invokable proof surface. Without it the
//! `CapabilityCellId` would be a well-formed string the process chose rather
//! than a catalogued capability.
//!
//! Ownership and direction:
//! - The generated block below is the compiled projection of
//!   `bins/eliot-mod-research/Cargo.toml::[package.metadata.eliot].functional_cell`
//!   and `bins/eliot-mod-research/capability-cell.contract.toml`. It is emitted
//!   by `scripts/gen_capability_cell_registry.py` and must not be hand-edited.
//! - `CapabilityCellRegistry::validate` is the #13 typed validator, not a second
//!   local shape check, so this module adds no parallel cell schema.
//! - The lookup is by the admission's own sealed `CapabilityCellId`, so a Kernel
//!   that admitted some other module id is refused rather than resolved against
//!   this package's cell.
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
const RESEARCH_PROVIDER_CAPABILITY_CELL_REGISTRY_JSON: &str = r#"{"cells":[{"affected_edges":[],"allowed_effect_classes":[],"cell":"mod-research-provider","cell_revision":{"major":1,"minor":0,"patch":0},"contract_digest":"fd0a6fbf1af1d4463ea2ced41576c8b1abf5ef2cd74a79a3716067486558d731","contract_digest_source":"bins/eliot-mod-research/capability-cell.contract.toml#contract-surface","execution_contour":"HOST_INLINE","freshness":{"current_support":"CURRENT_UNVERIFIED","invalidation":[]},"generation_owner":"issue-24","lifecycle_owner":"issue-24","maintenance_owner":"issue-24","manifest":{"context_capsule":{"owner":"issue-24","present":true},"contract_kit":{"owner":"issue-24","present":true},"test_capsule":{"owner":"issue-24","present":true}},"product_pulse":{"NOT_APPLICABLE":{"reason":"This provider bridge process is candidate-only research acquisition: a completed provider run proves process custody and evidence lineage, not research correctness, coverage, or product behavior. Product evidence is measured at the Kernel research route and the installed operational spine (#11)."}},"proof_ceiling":"STATIC_FIELD_AND_MIGRATION_CONTRACT_ONLY","proof_entrypoint":"cargo test -p eliot-mod-research --all-targets --all-features","removal_boundary":"Stop admitting research-provider dispatches, drain and cancel the exact eliot-mod-research process generation through Kernel, then remove the provider bridge; the Kernel research route answers CAPABILITY_UNAVAILABLE once the admitted material is no longer delivered.","replacement_class":"keep","runtime_bundle":null,"semantic_owner":"issue-24","source_crate":"eliot-mod-research","state_owners":[{"owner":"issue-24","state":"Per-operation admitted research-provider lifecycle: sealed admission, submitted envelope, raw provider evidence, provider job reference, terminal outcome, and cancellation receipt (in-process, per operation; no durable research Job/Attempt or coverage-denominator state)"}],"stateless":false}],"generator_version":"1.0.0","pair_key":"sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1","registry_version":1,"source_identity":{"cargo_lock_digest":"fc31e3176125cb717e6d665772d3181e11f7e11d64b3c47215402346b94863aa","generator_version":"1.0.0","toolchain":"rustc 1.97.1 (8bab26f4f 2026-07-14); binary: rustc; commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452; commit-date: 2026-07-14; host: x86_64-pc-windows-msvc; release: 1.97.1; LLVM version: 22.1.6","tree_digest":"df9a0818730023c9c56ddc95df827fda979a1e1706dc63a91e3787e085015dd6"}}"#;
// END GENERATED research-provider capability-cell registry

use std::sync::OnceLock;

use eliot_contracts::{CapabilityCellRegistry, SupportStatus};

use crate::admission::{AdmissionRefusal, ProviderAdmission};

/// The generated registry, decoded and validated at most once per process.
///
/// The registry is held **by value** here rather than as a borrow taken from the
/// closure that decodes it, so no borrow of `registry.cells` can outlive the
/// registry it points into. This is the same shape as
/// `bins/eliot-kernel/src/composition_bootstrap.rs::validated_native_worker_cell_registry`,
/// which also keeps its `CapabilityCellRegistry` by value in a `OnceLock` and
/// reads the cells out of it at the point of use.
static RESEARCH_PROVIDER_CELL: OnceLock<Result<CapabilityCellRegistry, String>> = OnceLock::new();

/// Re-verifies the admission's sealed capability cell against the generated record.
///
/// The record is re-verified here rather than merely looked up: the sealed
/// [`crate::admission::ProviderAdmission::module_id`] is compared **by value**
/// against the declared record's own cell identity, the record's source crate is
/// compared against the compiled package name, and its proof surface is required
/// to be present and current. A registry that merely *contains* a cell with this
/// name is not sufficient, and none of these comparisons can be satisfied by
/// existence alone.
///
/// # Errors
///
/// Returns [`AdmissionRefusal::UndeclaredCapabilityCell`] when the generated
/// registry cannot be typed-decoded or fails the #13 validator, when it declares
/// no cell for this package, or when that record names a different source crate;
/// [`AdmissionRefusal::CapabilityCellMismatch`] when the admission's sealed cell
/// id is not the declared cell; and
/// [`AdmissionRefusal::CapabilityCellUnsupported`] when the declared record
/// carries no independently invokable proof entrypoint or its current support is
/// stale or suspended. There is no default cell, no crate-name match, and no
/// partial acceptance.
pub fn resolve_admitted_cell(admission: &ProviderAdmission) -> Result<(), AdmissionRefusal> {
    let Ok(registry) = RESEARCH_PROVIDER_CELL.get_or_init(|| {
        let registry: CapabilityCellRegistry = serde_json::from_str(
            RESEARCH_PROVIDER_CAPABILITY_CELL_REGISTRY_JSON,
        )
        .map_err(|_| "embedded research-provider cell registry is not decodable".to_owned())?;
        registry
            .validate()
            .map_err(|_| "embedded research-provider cell registry failed validation".to_owned())?;
        Ok(registry)
    }) else {
        return Err(AdmissionRefusal::UndeclaredCapabilityCell);
    };
    // The admitted Module/Capability Registry reference must name the exact
    // declared cell. `ProviderAdmission` already shape-checked it through
    // `CapabilityCellId::new`; this is the record-side binding, so a Kernel that
    // admitted some other module id cannot be silently treated as this cell.
    let record = registry
        .cells
        .iter()
        .find(|record| record.cell.as_str() == RESEARCH_PROVIDER_CAPABILITY_CELL_ID)
        .ok_or(AdmissionRefusal::UndeclaredCapabilityCell)?;
    if admission.module_id().as_str() != record.cell.as_str() {
        return Err(AdmissionRefusal::CapabilityCellMismatch);
    }
    if record.source_crate.as_str() != RESEARCH_PROVIDER_CAPABILITY_SOURCE_PACKAGE {
        return Err(AdmissionRefusal::UndeclaredCapabilityCell);
    }
    // The admitted Module generation is deliberately not matched against the
    // record here. `CapabilityCellRecord::runtime_bundle` names a delegated
    // runtime bundle, and this cell declares none: it executes inline in this
    // process (`HOST_INLINE`). `ProviderAdmission::module_generation_id` is the
    // Module generation the Kernel admitted, which is a different namespace from
    // a runtime bundle, and reading one as the other would be a fabricated
    // delegation claim. The generation reference stays sealed and #13-typed on the
    // admission; the cell/proof binding this work unit owns is the cell identity
    // above and the proof surface below.
    if record.proof_entrypoint.is_none()
        || matches!(
            record.freshness.current_support,
            SupportStatus::Stale | SupportStatus::Suspended
        )
        || !record.freshness.invalidation.is_empty()
    {
        return Err(AdmissionRefusal::CapabilityCellUnsupported);
    }
    Ok(())
}
