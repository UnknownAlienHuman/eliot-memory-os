//! P03 parent drive for the WASM child contour (issue #1955, I14.19).
//!
//! The drive seats retained ports into a `WasmRuntime` invocation and
//! carries the evaluated lifecycle verdicts on the canonical response.
//! Order of operations over admitted values (never minted ones):
//!
//! ```text
//! typed material binding (dispatch_material::bind_dispatch_material)
//! → invocation assembly (assemble_request)
//! → progression gate (check_contour_prior: contract/conformance before
//!   effect-free shadow)
//! → contour admission over real bytes (contour_admission)
//! → authority/permit issuance (A3 execution join: dispatch_authority)
//! → P03 seating and reap (A3 execution join)
//! → verdict evaluation (evaluate_lifecycle_verdicts,
//!   evaluate_seated_verdicts)
//! ```
//!
//! This module implements the non-dependent seam now: drive errors, the
//! canonical `--guest-exec` argv assembly (byte-identical to the argv the
//! owner join gate derives), the contour-prior progression gate, invocation
//! and limit assembly from admitted material, contour admission over real
//! bytes, and the lifecycle/seated verdict evaluation over retained
//! execution evidence. Authority derivation/issuance and P03 seating join
//! with the A3 authority lane (`dispatch_authority`), which owns the grant
//! rebuild and the live permit; the drive consumes that lane's exact
//! field/type names and invents no admitted-caller assertions.
//!
//! A trap terminates the affected Store/instance or generation; it never
//! mutates Kernel state (I1.3). Cancellation, drain, and rollback are
//! lifecycle verdicts evaluated from the seated result, using the
//! `eliot-wasm-runtime::lifecycle` vocabulary (`InFlightDisposition`);
//! committing a cutover stays with the Kernel cutover path.

use std::path::Path;

use eliot_wasm_runtime::{
    ArtifactAccessLimits, CancellationPolicy, EpochPolicy, ExecutionContour,
    InvocationDisposition, InvocationLimits, InvocationRequest, InvocationResult, RuntimeError,
    Sha256Digest, TrapClass, VerificationVerdict,
};
use eliot_wasm_runtime::lifecycle::InFlightDisposition;

use crate::cli_contract::Profile;
use crate::dispatch_material::{
    MaterialError, ValidatedDispatchMaterial, ValidatedGuestCeilings,
};
use crate::installed_binary::InstalledBinaryError;

/// Exact `--guest-exec` argv assembled for the reaped child. Spellings
/// match the CLI contract; values are material-proven, never ambient.
pub const GUEST_EXEC_ARGV0_HINT: &str = "--guest-exec";

/// Fail-closed drive errors: pipeline stage plus stable detail. Codes only
/// — no digests, paths, or payloads echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DriveError {
    /// No dispatch material was delivered.
    NoMaterial,
    /// Material validation failed.
    Material(MaterialError),
    /// Installed-image resolution failed.
    Resolve(InstalledBinaryError),
    /// Intent derivation failed.
    Intent {
        /// Stable field name.
        field: &'static str,
    },
    /// Admission assembly failed (contour, records, limits).
    Admission {
        /// Stable field name.
        field: &'static str,
    },
    /// Invocation assembly or engine invocation failed.
    Invocation {
        /// Stable field name.
        field: &'static str,
    },
    /// Staging, start, reap, or capture failed.
    Execution {
        /// Stable stage name.
        stage: &'static str,
    },
}

impl std::fmt::Display for DriveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMaterial => formatter.write_str("DISPATCH_DRIVE_NO_MATERIAL"),
            Self::Material(error) => write!(formatter, "{error}"),
            Self::Resolve(error) => write!(formatter, "{error}"),
            Self::Intent { field } => write!(formatter, "DISPATCH_DRIVE_INTENT:{field}"),
            Self::Admission { field } => write!(formatter, "DISPATCH_DRIVE_ADMISSION:{field}"),
            Self::Invocation { field } => {
                write!(formatter, "DISPATCH_DRIVE_INVOCATION:{field}")
            }
            Self::Execution { stage } => write!(formatter, "DISPATCH_DRIVE_EXECUTION:{stage}"),
        }
    }
}

impl std::error::Error for DriveError {}

/// Canonical dispatch response: the guest output bytes plus the
/// tamper-evident facts binding them to the admitted operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchDriveResponse {
    /// Admitted operation identity.
    pub operation_id: String,
    /// Pinned component identity.
    pub component_id: String,
    /// Proven artifact digest (hex).
    pub artifact_digest: String,
    /// Proven input digest (hex).
    pub input_digest: String,
    /// Owner-measured host digest the child image resolved against (hex).
    pub host_artifact_digest: String,
    /// SHA-256 of the exact guest output bytes (hex).
    pub output_digest: String,
    /// Exact guest output bytes observed through P03 capture.
    pub output: Vec<u8>,
    /// Child-observed fuel consumed.
    pub fuel_consumed: u64,
    /// Child-observed peak memory bytes.
    pub peak_memory_bytes: u64,
    /// Child-observed table elements.
    pub table_elements: u64,
    /// Child-observed epoch ticks.
    pub epoch_ticks: u64,
    /// Lifecycle outcome verdicts evaluated from retained evidence.
    pub verdicts: LifecycleVerdicts,
    /// Seated trap/cancel/drain/rollback verdicts for the same run.
    pub seated: SeatedVerdicts,
}

/// Lifecycle outcome verdicts (A13.3 promotion path) evaluated from the
/// retained execution evidence of exactly one admitted operation. Shadow
/// is the only phase single-execution evidence can close: a completed,
/// effect-free, differential-agreeing run is the shadow observation
/// itself. Canary, rollback, and cutover are progression phases requiring
/// multi-evidence Governor decisions; they stay unevaluated (matching the
/// codebase convention that unevaluated verdicts read false), never
/// minted as verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleVerdicts {
    /// Effect-free completed differential-agreeing execution observed.
    pub shadow: VerificationVerdict,
    /// Bounded-canary progression evidence (never single-execution).
    pub canary: VerificationVerdict,
    /// Rollback execution evidence (none observed here).
    pub rollback: VerificationVerdict,
    /// Active-generation cutover evidence (none observed here).
    pub cutover: VerificationVerdict,
}

impl LifecycleVerdicts {
    /// All phases unevaluated: the closed value before any execution.
    #[must_use]
    pub const fn unevaluated() -> Self {
        use VerificationVerdict::Rejected;
        Self {
            shadow: Rejected,
            canary: Rejected,
            rollback: Rejected,
            cutover: Rejected,
        }
    }
}

/// Evaluates lifecycle verdicts from the retained Succeeded evidence.
/// The differential already matched (the runtime enforced it for
/// success), so shadow closes exactly when the completed run proposed no
/// effects and left a measured-empty state delta. Absent measurements
/// never manufacture verification: a missing delta reports Rejected.
/// Progression phases stay unevaluated.
///
/// The execution join calls this when projecting the seated result onto
/// the canonical dispatch response.
#[must_use]
pub fn evaluate_lifecycle_verdicts(result: &InvocationResult) -> LifecycleVerdicts {
    use VerificationVerdict::{Rejected, Verified};
    let shadow = match result.observed_state_delta.as_deref() {
        Some(delta) if delta.is_empty() && result.proposed_effects.is_empty() => Verified,
        _ => Rejected,
    };
    LifecycleVerdicts {
        shadow,
        ..LifecycleVerdicts::unevaluated()
    }
}

/// Seated trap/cancel/drain/rollback verdicts for exactly one admitted
/// operation, evaluated from the retained invocation result. Pure
/// classification over admitted evidence: a trap terminates the affected
/// Store/instance or generation without mutating Kernel state (I1.3);
/// drain dispositions reuse the `InFlightDisposition` vocabulary so the
/// cutover path consumes them without translation; rollback stays a
/// candidacy flag — committing a route switch belongs to the Kernel
/// cutover path, never to the drive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeatedVerdicts {
    /// Guest/host trap class when the engine reported a trap, else `None`.
    pub trap: Option<TrapClass>,
    /// True when the result reports cancellation.
    pub cancelled: bool,
    /// In-flight disposition for the cutover path when the operation left
    /// one; `None` when the operation never started (request denied before
    /// seating, or the engine was unavailable).
    pub drain: Option<InFlightDisposition>,
    /// True when the outcome implicates the generation (trap or unknown
    /// outcome) rather than just the request, so the Governor may consider
    /// a forward rollback proposal.
    pub rollback_candidate: bool,
}

/// Evaluates seated verdicts from one retained invocation result.
///
/// - Trap: the engine-reported [`TrapClass`], passed through untouched.
/// - Cancel: the runtime-reported `Cancelled` error.
/// - Drain: `Succeeded` reads drain while the fence holds
///   ([`InFlightDisposition::DrainRead`]); a succeeded run that proposed
///   effects may finish exactly the admitted operation under a committed
///   continuation permit
///   ([`InFlightDisposition::FinishExactAuthorizedOperation`]); a
///   cancellation with proven no-effect maps to
///   [`InFlightDisposition::CancelProvenNoEffect`]; an unknown outcome
///   blocks its scope until receipt/probe/reconciliation resolves it
///   ([`InFlightDisposition::BlockScopeUnknownOutcome`]). Denials before
///   seating leave nothing in flight.
/// - Rollback candidacy: traps and unknown outcomes implicate the
///   generation; request denials do not.
#[must_use]
pub fn evaluate_seated_verdicts(result: &InvocationResult) -> SeatedVerdicts {
    let trap = match &result.receipt.error {
        Some(RuntimeError::Trap(class)) => Some(*class),
        _ => None,
    };
    let cancelled = matches!(&result.receipt.error, Some(RuntimeError::Cancelled));
    let no_effects = result.proposed_effects.is_empty();
    let no_delta = result
        .observed_state_delta
        .as_deref()
        .is_none_or(<[u8]>::is_empty);
    let drain = match result.receipt.disposition {
        InvocationDisposition::Succeeded if no_effects => Some(InFlightDisposition::DrainRead),
        InvocationDisposition::Succeeded => {
            Some(InFlightDisposition::FinishExactAuthorizedOperation)
        }
        InvocationDisposition::Rejected if cancelled && no_effects && no_delta => {
            Some(InFlightDisposition::CancelProvenNoEffect)
        }
        InvocationDisposition::Rejected | InvocationDisposition::Unavailable => None,
        InvocationDisposition::Unknown => Some(InFlightDisposition::BlockScopeUnknownOutcome),
    };
    let rollback_candidate =
        trap.is_some() || matches!(result.receipt.disposition, InvocationDisposition::Unknown);
    SeatedVerdicts {
        trap,
        cancelled,
        drain,
        rollback_candidate,
    }
}

/// Progression gate: a Shadow operation must prove a prior
/// conformance-verified run for the exact current artifact (A13.3 order:
/// contract/conformance before effect-free shadow). Conformance enters
/// freely. Pure check over admitted values — no filesystem, no spawn.
fn check_contour_prior(
    contour: ExecutionContour,
    prior: Option<&Sha256Digest>,
    current_artifact: &Sha256Digest,
) -> Result<(), DriveError> {
    if !matches!(contour, ExecutionContour::Shadow) {
        return Ok(());
    }
    match prior {
        Some(previous) if previous.as_str() == current_artifact.as_str() => Ok(()),
        _ => Err(DriveError::Admission {
            field: "contour-prior",
        }),
    }
}

/// Builds the invocation request from admitted identities: invocation and
/// tree bind the operation and claim, work unit and scope bind the work
/// record, the contour binds the material marker, the input is the proven
/// guest bytes, and the seed is owner-set. Cancellation is never
/// requested by the drive; it arrives through the cancel path.
fn assemble_request(material: &ValidatedDispatchMaterial) -> Result<InvocationRequest, DriveError> {
    use eliot_wasm_runtime::{CapabilityId, InvocationId, WorkScopeRef, WorkUnitId};
    let invoked = |field: &'static str| DriveError::Admission { field };
    let contour = match material.work.contour.as_str() {
        "SHADOW" => ExecutionContour::Shadow,
        "CONFORMANCE" => ExecutionContour::Conformance,
        _ => return Err(invoked("contour")),
    };
    InvocationRequest::new(
        InvocationId::new(material.operation_id.clone()).map_err(|_| invoked("invocation-id"))?,
        CapabilityId::new(material.ceilings.component_id.clone())
            .map_err(|_| invoked("component-id"))?,
        WorkUnitId::new(material.work.work_unit.clone()).map_err(|_| invoked("work-unit"))?,
        WorkScopeRef::new(material.work.work_scope.clone()).map_err(|_| invoked("work-scope"))?,
        contour,
        material.input_bytes.clone(),
        material.work.deterministic_seed,
        false,
    )
    .map_err(|_| invoked("request"))
}

/// Assembles the per-invocation limit envelope from material ceilings plus
/// frozen contour constants. Input ceiling tracks the real input length
/// (ceilings bound, never shrink, reality); host-call ceiling stays at the
/// closed-world minimum; stack and cancellation stay provider-pinned.
fn assemble_limits(material: &ValidatedDispatchMaterial) -> Result<InvocationLimits, DriveError> {
    let ceilings = &material.ceilings;
    let limited = |field: &'static str| DriveError::Admission { field };
    Ok(InvocationLimits {
        max_input_bytes: (material.input_bytes.len() as u64).max(1),
        max_output_bytes: ceilings.max_output_bytes,
        max_host_calls: 1,
        max_fuel: ceilings.max_fuel,
        max_memory_bytes: ceilings.max_memory_bytes,
        max_table_elements: u32::try_from(ceilings.table_elements)
            .map_err(|_| limited("table-elements"))?,
        max_instances: u32::try_from(ceilings.max_instances).map_err(|_| limited("instances"))?,
        max_stack_bytes: crate::wasmtime_provider::PROVIDER_STACK_SIZE as u64,
        wall_deadline_ms: ceilings.wall_deadline_ms,
        epoch: EpochPolicy {
            deadline_ticks: ceilings.epoch_deadline_ticks,
            cancellation: CancellationPolicy::EpochAndFuel,
        },
        artifact_access: ArtifactAccessLimits {
            allowed_digests: [ceilings.artifact_digest.clone()].into_iter().collect(),
            max_reads: u32::try_from(ceilings.artifact_access_reads)
                .map_err(|_| limited("artifact-reads"))?,
            max_bytes: ceilings.artifact_access_bytes,
        },
    })
}

/// Builds the closed-world generation manifest from material records plus
/// recomputed digests, then runs the documented contour admission over
/// real bytes: default WASM decision, artifact digest re-hash, empty
/// actual imports, and request binding. Returns the manifest for owner
/// assembly plus the admitted generation the request must match.
///
/// The WIT digest binds the frozen typed world
/// (`typed_bindings::typed_wit_digest`): the byte-verified WIT admission
/// joins when a canonical WIT-bytes source lands. Artifact bytes are
/// proven here (manifest agreement) and re-proven by the child re-hash at
/// invoke.
fn contour_admission(
    material: &ValidatedDispatchMaterial,
    request: &InvocationRequest,
) -> Result<
    (
        crate::contour::GenerationManifest,
        crate::contour::AdmittedGeneration,
    ),
    DriveError,
> {
    let denied = |field: &'static str| DriveError::Admission { field };
    let manifest = crate::contour::GenerationManifest {
        component_id: material.manifest.component_id.clone(),
        target: material.manifest.target.clone(),
        artifact_digest: Sha256Digest::of_bytes(&material.artifact_bytes),
        wit_digest: crate::typed_bindings::typed_wit_digest(),
        world: material.manifest.world.clone(),
        allowed_imports: Vec::new(),
        allowed_exports: vec!["run".to_owned()],
        capability_grants: Vec::new(),
        limits: assemble_limits(material)?,
        state_class: material.manifest.state_class.clone(),
        migration_contract: material.manifest.migration_contract.clone(),
        privacy_policy: material.manifest.privacy_policy.clone(),
        comparator: material.manifest.comparator.clone(),
        rollback_generation: material.manifest.rollback_generation.clone(),
    };
    if manifest.artifact_digest != material.ceilings.artifact_digest
        || manifest.component_id != material.ceilings.component_id
    {
        return Err(denied("manifest-agreement"));
    }
    let decision = crate::contour::PrototypeContourDecision::default_for_new_prototype();
    let admitted = crate::contour::admit_generation(Some(&decision), &manifest, &[])
        .map_err(|_| denied("contour-admission"))?;
    crate::contour::check_admitted_request(&admitted, request)
        .map_err(|_| denied("request-binding"))?;
    Ok((manifest, admitted))
}

/// Assembles the canonical `--guest-exec` argv for the reaped child:
/// `--profile <profile>` first, then the `--guest-exec` spellings the CLI
/// contract parses. Byte-identical to the argv the owner join gate
/// derives, so both sides close over the same intent. Pure assembly over
/// admitted values — no filesystem, no spawn.
#[must_use]
pub fn guest_exec_argv(
    profile: Profile,
    artifact_path: &Path,
    input_path: &Path,
    ceilings: &ValidatedGuestCeilings,
) -> Vec<String> {
    vec![
        "--profile".to_owned(),
        profile.as_str().to_owned(),
        GUEST_EXEC_ARGV0_HINT.to_owned(),
        "--guest-exec-artifact".to_owned(),
        artifact_path.to_string_lossy().into_owned(),
        "--guest-exec-input".to_owned(),
        input_path.to_string_lossy().into_owned(),
        "--guest-exec-artifact-digest".to_owned(),
        ceilings.artifact_digest.as_str().to_owned(),
        "--guest-exec-max-output".to_owned(),
        ceilings.max_output_bytes.to_string(),
        "--guest-exec-max-fuel".to_owned(),
        ceilings.max_fuel.to_string(),
        "--guest-exec-max-memory".to_owned(),
        ceilings.max_memory_bytes.to_string(),
        "--guest-exec-wall-ms".to_owned(),
        ceilings.wall_deadline_ms.to_string(),
        "--guest-exec-epoch-ticks".to_owned(),
        ceilings.epoch_deadline_ticks.to_string(),
    ]
}

/// Runs the pre-seating drive pipeline over validated material: invocation
/// assembly, the contour-prior progression gate, and contour admission
/// over real bytes. Returns the assembled request plus the admitted
/// generation the authority/permit join consumes. Pure over admitted
/// values — no authority, permit, filesystem, or spawn.
pub fn drive_admission(
    material: &ValidatedDispatchMaterial,
) -> Result<(InvocationRequest, crate::contour::AdmittedGeneration), DriveError> {
    let request = assemble_request(material)?;
    // Progression gate: Shadow operations must prove a prior
    // conformance-verified run for the exact current artifact (A13.3
    // order: contract/conformance before effect-free shadow).
    // Conformance enters freely; canary/active never reach here (the
    // envelope spelling check admits only Shadow/Conformance).
    let contour = match material.work.contour.as_str() {
        "SHADOW" => ExecutionContour::Shadow,
        _ => ExecutionContour::Conformance,
    };
    check_contour_prior(
        contour,
        material.prior_conformance_artifact.as_ref(),
        &material.ceilings.artifact_digest,
    )?;
    // Contour admission over real bytes: manifest assembly, default WASM
    // decision, byte re-hash, request binding. A divergent fixture is
    // denied before any authority, permit, or child exists.
    let (_, admitted) = contour_admission(material, &request)?;
    Ok((request, admitted))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dispatch_material::{
        DispatchMaterialInput, ValidatedAssuranceInput, ValidatedGuestCeilingsInput,
        ValidatedManifestInput, ValidatedPromotionInput, ValidatedSnapshotInput, ValidatedWorkInput,
        bind_dispatch_material,
    };

    fn digest_of(bytes: &[u8]) -> String {
        Sha256Digest::of_bytes(bytes).as_str().to_owned()
    }

    fn test_material() -> ValidatedDispatchMaterial {
        let artifact = b"drive-artifact-bytes".to_vec();
        let input = b"drive-input-bytes".to_vec();
        let epoch_json =
            "{\"lineage_id\":\"550e8400-e29b-41d4-a716-446655440000\",\"sequence\":3}".to_owned();
        bind_dispatch_material(DispatchMaterialInput {
            claim_id: "claim-drive-001".to_owned(),
            operation_id: "operation-drive-001".to_owned(),
            generation: 7,
            authority_epoch_json: epoch_json.clone(),
            launch_nonce: "launch-nonce-drive-0001".to_owned(),
            admitted_at_unix_ms: 4_000_000_000_000,
            grant_digest: "e".repeat(64),
            grant_fence_generation: 7,
            grant_fence_nonce: "wasm-host-launch-fence-aaaaaaaaaaaaaaaa".to_owned(),
            grant_idempotency_key: "wasm-host-launch-lease-aaaaaaaaaaaaaaaa".to_owned(),
            grant_expires_at: 4_000_000_060_000,
            host_artifact_digest: "d".repeat(64),
            profile: "D2_OPERATIONAL".to_owned(),
            prior_conformance_artifact: None,
            ceilings: ValidatedGuestCeilingsInput {
                component_id: "component-drive".to_owned(),
                artifact_digest: digest_of(&artifact),
                input_digest: digest_of(&input),
                max_output_bytes: 4096,
                max_fuel: 100_000,
                max_memory_bytes: 536_870_912,
                wall_deadline_ms: 30_000,
                epoch_deadline_ticks: 100,
                table_elements: 64,
                max_instances: 2,
                artifact_access_reads: 2,
                artifact_access_bytes: 131_072,
            },
            manifest: ValidatedManifestInput {
                component_id: "component-drive".to_owned(),
                world: "eliot:wasm/guest".to_owned(),
                target: "wasm32-wasip2".to_owned(),
                source_digest: "b".repeat(64),
                state_contract_digest: "f".repeat(64),
                required_verifier: "verifier:a12".to_owned(),
                privacy_classes: vec!["Internal".to_owned()],
                state_class: "stateless".to_owned(),
                migration_contract: "none".to_owned(),
                privacy_policy: "project_code".to_owned(),
                comparator: "shadow-exact".to_owned(),
                rollback_generation: None,
            },
            work: ValidatedWorkInput {
                owner: "owner-drive".to_owned(),
                work_unit: "work-drive".to_owned(),
                work_scope: "scope-drive".to_owned(),
                task_ref: None,
                lease_id: "lease-drive".to_owned(),
                lease_scope_ref: "scope-drive".to_owned(),
                lease_state: "active".to_owned(),
                generation_state: "ready".to_owned(),
                authority_revision: 1,
                lifecycle_revision: 1,
                verification_revision: 1,
                deterministic_seed: 7,
                contour: "CONFORMANCE".to_owned(),
                generation_health: vec!["HEALTHY".to_owned(); 6],
            },
            assurance: ValidatedAssuranceInput {
                source_ref: "source-drive".to_owned(),
                provenance_ref: "provenance-drive".to_owned(),
                integrity: "VERIFIED".to_owned(),
                freshness: "CURRENT".to_owned(),
                competence: "DOMAIN_VERIFIED".to_owned(),
                independence: "INDEPENDENT".to_owned(),
                privacy_class: "INTERNAL".to_owned(),
                instruction_taint: "DATA_ONLY".to_owned(),
                epistemic_use: vec!["VERIFICATION_INPUT".to_owned()],
                effect_ceilings: vec!["NO_EXTERNAL_EFFECT".to_owned()],
                required_verifier: "verifier:a12".to_owned(),
                quarantine: "NONE".to_owned(),
            },
            promotion: ValidatedPromotionInput {
                corpus_digest: "0".repeat(64),
                expected_result_digest: "1".repeat(64),
                expected_effect_digest: "2".repeat(64),
                expected_state_delta_digest: "3".repeat(64),
            },
            snapshot: ValidatedSnapshotInput {
                service: "eliot-kernel".to_owned(),
                protocol: "eliot.kernel.v1".to_owned(),
                generation: 7,
                authority_epoch_json: epoch_json,
                artifact_digest: "a".repeat(64),
                protected_snapshot_digest: "b".repeat(64),
                principal: "S-1-5-18".to_owned(),
            },
            artifact_bytes: artifact,
            input_bytes: input,
        })
        .expect("drive material binds")
    }

    /// Progression gate cases: Conformance enters with or without prior;
    /// Shadow requires the exact current artifact digest and denies
    /// absence or foreign digests.
    #[test]
    fn contour_prior_gate_enforces_progression() {
        let current = Sha256Digest::of_bytes(b"current-artifact");
        let prior = Sha256Digest::of_bytes(b"current-artifact");
        let foreign = Sha256Digest::of_bytes(b"foreign-artifact");
        assert!(check_contour_prior(ExecutionContour::Conformance, None, &current).is_ok());
        assert!(
            check_contour_prior(ExecutionContour::Conformance, Some(&foreign), &current).is_ok()
        );
        assert!(check_contour_prior(ExecutionContour::Shadow, Some(&prior), &current).is_ok());
        assert_eq!(
            check_contour_prior(ExecutionContour::Shadow, None, &current),
            Err(DriveError::Admission {
                field: "contour-prior"
            })
        );
        assert_eq!(
            check_contour_prior(ExecutionContour::Shadow, Some(&foreign), &current),
            Err(DriveError::Admission {
                field: "contour-prior"
            })
        );
    }

    /// Canonical intent pin: the derived argv carries exactly the
    /// admitted profile, the staged paths, and the material ceilings in
    /// the owner-join order (`--profile` first).
    #[test]
    fn guest_exec_argv_pins_canonical_intent() {
        let material = test_material();
        let argv = guest_exec_argv(
            material.profile,
            Path::new("C:\\Kernel\\eliot-wasm-host.guest-artifact.bin"),
            Path::new("C:\\Kernel\\eliot-wasm-host.guest-input.bin"),
            &material.ceilings,
        );
        assert_eq!(
            argv,
            vec![
                "--profile".to_owned(),
                "D2_OPERATIONAL".to_owned(),
                "--guest-exec".to_owned(),
                "--guest-exec-artifact".to_owned(),
                "C:\\Kernel\\eliot-wasm-host.guest-artifact.bin".to_owned(),
                "--guest-exec-input".to_owned(),
                "C:\\Kernel\\eliot-wasm-host.guest-input.bin".to_owned(),
                "--guest-exec-artifact-digest".to_owned(),
                digest_of(b"drive-artifact-bytes"),
                "--guest-exec-max-output".to_owned(),
                "4096".to_owned(),
                "--guest-exec-max-fuel".to_owned(),
                "100000".to_owned(),
                "--guest-exec-max-memory".to_owned(),
                "536870912".to_owned(),
                "--guest-exec-wall-ms".to_owned(),
                "30000".to_owned(),
                "--guest-exec-epoch-ticks".to_owned(),
                "100".to_owned(),
            ]
        );
    }

    /// Pre-seating pipeline: invocation assembly binds the admitted
    /// identities, contour admission closes over real bytes, and the
    /// admitted generation matches the request.
    #[test]
    fn drive_admission_binds_request_to_generation() {
        let material = test_material();
        let (request, admitted) = drive_admission(&material).expect("drive admits");
        assert_eq!(request.component_id.as_str(), "component-drive");
        assert_eq!(admitted.component_id(), "component-drive");
        assert_eq!(admitted.artifact_digest().as_str(), digest_of(b"drive-artifact-bytes"));
        // Shadow without a prior conformance proof denies pre-seating.
        let mut shadow = test_material();
        shadow.work.contour = "SHADOW".to_owned();
        assert_eq!(
            drive_admission(&shadow).map(|_| ()),
            Err(DriveError::Admission {
                field: "contour-prior"
            })
        );
    }

    fn succeeded_result() -> InvocationResult {
        use eliot_wasm_runtime::{CapabilityId, InvocationId, WorkScopeRef, WorkUnitId};
        let request = InvocationRequest::new(
            InvocationId::new("operation-drive-001").expect("invocation"),
            CapabilityId::new("component-drive").expect("component"),
            WorkUnitId::new("work-drive").expect("work unit"),
            WorkScopeRef::new("scope-drive").expect("scope"),
            ExecutionContour::Shadow,
            b"drive-input-bytes".to_vec(),
            7,
            false,
        )
        .expect("request builds");
        InvocationResult {
            receipt: eliot_wasm_runtime::InvocationReceipt {
                invocation_id: request.invocation_id.clone(),
                request_digest: request.request_digest().clone(),
                disposition: InvocationDisposition::Succeeded,
                error: None,
                output_digest: Some(Sha256Digest::of_bytes(b"drive-output")),
                effect_digest: None,
                state_delta_digest: Some(Sha256Digest::of_bytes(b"")),
                engine_binding: None,
                usage: None,
                reconciliation_required: false,
            },
            output: Some(b"drive-output".to_vec()),
            proposed_effects: Vec::new(),
            observed_state_delta: Some(Vec::new()),
        }
    }

    /// Verdict evaluation: an effect-free succeeded shadow run closes the
    /// shadow verdict and drains reads; traps, cancels, and unknown
    /// outcomes classify without minting progression.
    #[test]
    fn seated_verdicts_classify_retained_evidence() {
        use VerificationVerdict::{Rejected, Verified};
        let ok = succeeded_result();
        assert_eq!(
            evaluate_lifecycle_verdicts(&ok),
            LifecycleVerdicts {
                shadow: Verified,
                canary: Rejected,
                rollback: Rejected,
                cutover: Rejected,
            }
        );
        assert_eq!(
            evaluate_seated_verdicts(&ok),
            SeatedVerdicts {
                trap: None,
                cancelled: false,
                drain: Some(InFlightDisposition::DrainRead),
                rollback_candidate: false,
            }
        );
        // Trap: class passes through, generation implicated, scope blocked.
        let mut trapped = succeeded_result();
        trapped.receipt.disposition = InvocationDisposition::Rejected;
        trapped.receipt.error = Some(RuntimeError::Trap(TrapClass::GuestTrap));
        trapped.output = None;
        trapped.observed_state_delta = None;
        assert_eq!(
            evaluate_seated_verdicts(&trapped),
            SeatedVerdicts {
                trap: Some(TrapClass::GuestTrap),
                cancelled: false,
                drain: None,
                rollback_candidate: true,
            }
        );
        // Cancel with proven no-effect drains as cancelled.
        let mut cancelled = succeeded_result();
        cancelled.receipt.disposition = InvocationDisposition::Rejected;
        cancelled.receipt.error = Some(RuntimeError::Cancelled);
        cancelled.output = None;
        assert_eq!(
            evaluate_seated_verdicts(&cancelled),
            SeatedVerdicts {
                trap: None,
                cancelled: true,
                drain: Some(InFlightDisposition::CancelProvenNoEffect),
                rollback_candidate: false,
            }
        );
        // Unknown outcome blocks its scope and implicates the generation.
        let mut unknown = succeeded_result();
        unknown.receipt.disposition = InvocationDisposition::Unknown;
        unknown.receipt.error = Some(RuntimeError::UnknownOutcome);
        unknown.receipt.reconciliation_required = true;
        assert_eq!(
            evaluate_seated_verdicts(&unknown),
            SeatedVerdicts {
                trap: None,
                cancelled: false,
                drain: Some(InFlightDisposition::BlockScopeUnknownOutcome),
                rollback_candidate: true,
            }
        );
    }
}
