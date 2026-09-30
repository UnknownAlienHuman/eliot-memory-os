//! Pure projection from the host's parallel [`TypedReceipt`] to #760's
//! shared `eliot_wasm_runtime::TypedReceipt`.
//!
//! The host receipt (one bounded engine/run record per typed call) carries
//! Wasmtime-provider evidence the neutral contract does not own:
//! `engine_version`, `wit_digest`, `cache_identity`, `actual_imports`,
//! `actual_exports`, `input_bytes`, `fuel_consumed`, `peak_memory_bytes`,
//! `table_elements`, `instances`, the admitted `operation_id`/`task_id`/
//! `fence_epoch`/`policy_id` echo, `artifact_bytes`, and the observation-only
//! `elapsed_ms`. None of those fields is repaired into a neutral shape here;
//! they stay host-owned and are dropped by the projection, never faked.
//!
//! The two shared fields no host receipt carries must arrive from the caller
//! with their source named at the call site, never invented here:
//! `kit_digest` is the digest of the governing [`ModuleContractKit`] (its
//! `digest`, which binds package/world/ABI/artifact/interface/declared
//! imports/exports/state contract/ceiling), and `proof_ceiling` is the
//! admitted ceiling (`ModuleContractKit::proof_ceiling`, or the admitted
//! envelope on a kit-less lane). Kit-less lanes (the describe-only path and
//! the unbound domain path) have no honest `kit_digest` source and must not
//! call this projection until a kit owner binds one.
//!
//! The projected receipt is validated by the shared `validate` before it is
//! returned: exact package identity, bounded terminal, and the output
//! invariant (output bytes exist exactly when an output digest exists). The
//! shared `semantic_digest` is recomputed over the shared fields only, so
//! observation timing stays separate from deterministic semantic identity.
//! Projection success still means one bounded typed call, never candidate
//! application, use, or task completion.
//!
//! [`ModuleContractKit`]: eliot_wasm_runtime::capsule::ModuleContractKit
//! [`TypedReceipt`]: crate::typed_execution::TypedReceipt

use eliot_wasm_runtime::ProofStage;
use eliot_wasm_runtime::Sha256Digest;
use eliot_wasm_runtime::component_contract::{ProofCeiling, TypedContractError};

use crate::typed_execution::{TypedExecutionError, TypedReceipt, TypedStage};

/// Projects one host typed receipt onto #760's shared contract.
///
/// `kit_digest` is the caller-supplied digest of the governing kit and
/// `proof_ceiling` is the caller-supplied admitted ceiling; both sources are
/// named at the call site. Every failure is a typed
/// [`TypedExecutionError`]: an unparsable world is `WorldUnknown`, a legacy
/// world is `LegacyMismatch`, an unknown host stage code or a shared
/// validation denial is the owned typed denial with the same fail-closed
/// meaning. There is no stringly catch-all and no `Value`/string repair.
///
/// # Errors
///
/// Returns the owned typed denial when the host world, stage, or package/
/// terminal/output fields cannot honestly satisfy the shared contract.
pub fn project_shared_receipt(
    receipt: &TypedReceipt,
    kit_digest: &Sha256Digest,
    proof_ceiling: ProofCeiling,
) -> Result<eliot_wasm_runtime::TypedReceipt, TypedExecutionError> {
    let world = match eliot_wasm_runtime::component_contract::TypedWorld::parse(&receipt.world) {
        Ok(world) => world,
        Err(TypedContractError::UnknownWorld(got)) => {
            return Err(TypedExecutionError::WorldUnknown(got));
        }
        Err(TypedContractError::LegacyRejected(_)) => {
            return Err(TypedExecutionError::LegacyMismatch);
        }
        Err(_) => {
            return Err(TypedExecutionError::WorldUnknown(bounded_identity(
                &receipt.world,
            )));
        }
    };
    let stage = project_stage(&receipt.stage)?;
    // The shared invariant is exact: output bytes exist exactly when an
    // output digest exists. Successful host receipts always measure output,
    // so the digest is carried; a zero-byte receipt carries no output digest.
    let output_digest = if receipt.output_bytes == 0 {
        None
    } else {
        Some(receipt.output_digest.clone())
    };
    let mut shared = eliot_wasm_runtime::TypedReceipt {
        kit_digest: kit_digest.clone(),
        world,
        package_id: receipt.package_id.clone(),
        artifact_digest: receipt.artifact_digest.clone(),
        input_digest: receipt.input_digest.clone(),
        output_digest,
        output_bytes: receipt.output_bytes,
        stage,
        proof_ceiling,
        terminal: receipt.terminal.clone(),
        semantic_digest: Sha256Digest::of_bytes(b"typed-shared-semantic-pending"),
    };
    shared.semantic_digest = shared_semantic_digest(&shared);
    shared.validate().map_err(map_shared_validation)?;
    Ok(shared)
}

/// Maps one host pipeline stage code to the separated shared proof stage.
/// Each host stage names the proof its completion would support; parity has
/// no host counterpart and is never produced here.
fn project_stage(stage: &str) -> Result<ProofStage, TypedExecutionError> {
    if stage == TypedStage::Compile.as_str() {
        Ok(ProofStage::Build)
    } else if stage == TypedStage::Instantiate.as_str() {
        Ok(ProofStage::Instantiation)
    } else if stage == TypedStage::Descriptor.as_str() {
        Ok(ProofStage::Abi)
    } else if stage == TypedStage::Invoke.as_str() {
        Ok(ProofStage::Invocation)
    } else if stage == TypedStage::Output.as_str() {
        Ok(ProofStage::Result)
    } else if stage == TypedStage::Cleanup.as_str() {
        Ok(ProofStage::Receipt)
    } else {
        Err(TypedExecutionError::OutputViolation("stage".to_owned()))
    }
}

/// Maps a shared receipt-validation denial to the exact owned typed denial
/// with the same fail-closed meaning. Failures stay typed.
fn map_shared_validation(error: TypedContractError) -> TypedExecutionError {
    match error {
        TypedContractError::PackageMismatch { .. } => {
            TypedExecutionError::AdmissionMismatch("package".to_owned())
        }
        TypedContractError::DescriptorField(field) => TypedExecutionError::AdmissionMismatch(field),
        TypedContractError::ReportMismatch => {
            TypedExecutionError::AdmissionMismatch("shared-report".to_owned())
        }
        _ => TypedExecutionError::AdmissionMismatch("shared-receipt".to_owned()),
    }
}

/// Deterministic semantic digest over the shared receipt fields only:
/// kit, world, package, artifact, input, output, stage, ceiling, terminal.
/// Observation timing is excluded by construction: the shared receipt
/// carries no wall time, fuel, or peak measurements, and the host-only
/// evidence dropped by the projection is never hashed here.
fn shared_semantic_digest(receipt: &eliot_wasm_runtime::TypedReceipt) -> Sha256Digest {
    fn push_field(canonical: &mut Vec<u8>, value: &[u8]) {
        canonical.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        canonical.extend_from_slice(value);
    }

    let mut canonical = b"eliot-shared-typed-semantic/v1\0".to_vec();
    push_field(&mut canonical, receipt.kit_digest.as_str().as_bytes());
    push_field(&mut canonical, receipt.world.world_name().as_bytes());
    push_field(&mut canonical, receipt.package_id.as_bytes());
    push_field(&mut canonical, receipt.artifact_digest.as_str().as_bytes());
    push_field(&mut canonical, receipt.input_digest.as_str().as_bytes());
    match &receipt.output_digest {
        Some(digest) => push_field(&mut canonical, digest.as_str().as_bytes()),
        None => push_field(&mut canonical, b"none"),
    }
    push_field(&mut canonical, &receipt.output_bytes.to_be_bytes());
    push_field(&mut canonical, proof_stage_code(receipt.stage).as_bytes());
    push_field(
        &mut canonical,
        proof_ceiling_code(receipt.proof_ceiling).as_bytes(),
    );
    push_field(&mut canonical, receipt.terminal.as_bytes());
    Sha256Digest::of_bytes(&canonical)
}

/// Stable wire code for one shared proof stage (its canonical serde form).
const fn proof_stage_code(stage: ProofStage) -> &'static str {
    match stage {
        ProofStage::Build => "BUILD",
        ProofStage::Abi => "ABI",
        ProofStage::Instantiation => "INSTANTIATION",
        ProofStage::Invocation => "INVOCATION",
        ProofStage::Result => "RESULT",
        ProofStage::Parity => "PARITY",
        ProofStage::Receipt => "RECEIPT",
    }
}

/// Stable wire code for one shared proof ceiling (its canonical serde form).
const fn proof_ceiling_code(ceiling: ProofCeiling) -> &'static str {
    match ceiling {
        ProofCeiling::Observation => "observation",
        ProofCeiling::CandidateOnly => "candidate-only",
        ProofCeiling::Admission => "admission",
        ProofCeiling::Assembly => "assembly",
        ProofCeiling::Activation => "activation",
        ProofCeiling::Screen => "screen",
        ProofCeiling::Cycle => "cycle",
        ProofCeiling::Handler => "handler",
    }
}

/// Bounds an unparsable host world for a typed denial: identity only, never
/// payload, path, or secret.
fn bounded_identity(value: &str) -> String {
    value.chars().take(96).collect()
}
