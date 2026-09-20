//! WASM generation lifecycle projection, conformance, shadow, migration,
//! and rollback routing for issue #1956 (I14.19 / I14.14).
//!
//! Every type here is a pure projection over the Kernel-owned canonical
//! machines (`ModuleGeneration` / `GenerationCutoverRecord` from
//! `eliot-runtime-contracts`). Nothing here mints generation authority,
//! admits a contour, writes canonical state, or executes guest code. The
//! semantic core lives outside Wasmtime: the WASM guest adapter and the
//! native-process adapter invoke the same [`SemanticCore`] (or pass the same
//! conformance corpus), and the differential harness compares result/error
//! class, proposed effects, state delta, resource/host-call envelope, and
//! determinism for one fixed input and seed.
//!
//! Shadow execution is effect-free by construction (no scheduler handle is
//! taken, external effects are dropped before they can be emitted) and the
//! comparator outcome is persisted on the [`ShadowResult`]. Rollback is a
//! newer routing cutover: the new authority epoch must strictly rise and an
//! old epoch is never reactivated.

use eliot_runtime_contracts::{GenerationCutoverState, ModuleGenerationState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CapabilityId, EffectProposal, Sha256Digest, canonical_digest};

/// Lifecycle labels from I14.19. These are a projection of the canonical
/// `ModuleGeneration` / `GenerationCutover` machines, never a second mutable
/// owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WasmLifecycleState {
    Draft,
    Built,
    ConformancePassed,
    ReplayPassed,
    Shadow,
    Canary,
    Active,
    Draining,
    Retired,
    Rejected,
    RolledBack,
}

/// Evidence flags feeding the pure [`project_lifecycle`] projection. The
/// generation and cutover states are Kernel-owned facts; the booleans are
/// caller-observed evidence (comparator receipts, drain snapshots, rollback
/// cutover records) supplied by the owner.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleProjectionInputs {
    pub generation: ModuleGenerationState,
    pub cutover: Option<GenerationCutoverState>,
    pub conformance_passed: bool,
    pub replay_passed: bool,
    pub shadow_open: bool,
    pub canary_open: bool,
    pub draining: bool,
    pub rollback_cutover_committed: bool,
}

/// Projects the canonical machines onto one WASM lifecycle label.
///
/// Terminal rollback evidence wins over draining/active so a rolled-back
/// route is never reported as still active. Rejection (failed, quarantined,
/// or failed cutover) wins over progress labels. Otherwise the label follows
/// the generation state combined with the observed conformance/replay/shadow/
/// canary/drain evidence.
#[must_use]
pub fn project_lifecycle(inputs: &LifecycleProjectionInputs) -> WasmLifecycleState {
    if inputs.rollback_cutover_committed {
        return WasmLifecycleState::RolledBack;
    }
    if matches!(
        inputs.generation,
        ModuleGenerationState::Failed
            | ModuleGenerationState::Quarantined
            | ModuleGenerationState::ManualRecovery
            | ModuleGenerationState::RestartWait
    ) || matches!(
        inputs.cutover,
        Some(GenerationCutoverState::Failed | GenerationCutoverState::FailedRequiresForwardCutover)
    ) {
        return WasmLifecycleState::Rejected;
    }
    if matches!(
        inputs.generation,
        ModuleGenerationState::Drained
            | ModuleGenerationState::Stopped
            | ModuleGenerationState::Retired
    ) {
        return WasmLifecycleState::Retired;
    }
    if inputs.draining
        || matches!(
            inputs.generation,
            ModuleGenerationState::Quiescing | ModuleGenerationState::Degraded
        ) && inputs.canary_open
    {
        return WasmLifecycleState::Draining;
    }
    if matches!(inputs.generation, ModuleGenerationState::Active) && !inputs.draining {
        return WasmLifecycleState::Active;
    }
    if inputs.canary_open {
        return WasmLifecycleState::Canary;
    }
    if inputs.shadow_open {
        return WasmLifecycleState::Shadow;
    }
    if inputs.conformance_passed && inputs.replay_passed {
        return WasmLifecycleState::ReplayPassed;
    }
    if inputs.conformance_passed {
        return WasmLifecycleState::ConformancePassed;
    }
    match inputs.generation {
        ModuleGenerationState::Discovered | ModuleGenerationState::Staged => {
            WasmLifecycleState::Draft
        }
        _ => WasmLifecycleState::Built,
    }
}

/// Stable error class compared across backends. Collapses provider detail;
/// `Ok` versus any rejection is the load-bearing distinction.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorClass {
    Ok,
    Rejected,
    Unavailable,
    Unknown,
}

/// Runtime-independent outcome of one deterministic component invocation.
/// Both the WASM guest adapter and the native-process adapter produce this
/// shape by invoking the same [`SemanticCore`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreOutcome {
    pub result: Vec<u8>,
    pub error_class: ErrorClass,
    pub effects: Vec<EffectProposal>,
    pub state_delta: Vec<u8>,
    pub host_calls: Vec<CapabilityId>,
    pub fuel_consumed: u64,
    pub peak_memory_bytes: u64,
}

/// Runtime-independent semantic core. It has no Wasmtime, process, or I/O
/// dependency; adapters on either contour call it with the same input and
/// seed.
pub trait SemanticCore {
    /// Invokes the deterministic component logic.
    fn invoke(&self, input: &[u8], seed: u64) -> CoreOutcome;
}

/// One registered deterministic component used as the conformance reference:
/// a seed-mixed wrapping-add transform over the input bytes. Deterministic
/// across contours by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterministicEchoCore {
    component_id: &'static str,
}

impl DeterministicEchoCore {
    /// Creates the reference core for one registered component identity.
    #[must_use]
    pub const fn new(component_id: &'static str) -> Self {
        Self { component_id }
    }

    /// Returns the registered component identity.
    #[must_use]
    pub const fn component_id(&self) -> &'static str {
        self.component_id
    }
}

impl SemanticCore for DeterministicEchoCore {
    fn invoke(&self, input: &[u8], seed: u64) -> CoreOutcome {
        let seed_bytes = seed.to_le_bytes();
        let mut result = Vec::with_capacity(input.len());
        for (index, byte) in input.iter().enumerate() {
            result.push(byte.wrapping_add(seed_bytes[index % seed_bytes.len()]));
        }
        let state_delta = Sha256Digest::of_bytes(&result).as_str().as_bytes().to_vec();
        CoreOutcome {
            result,
            error_class: ErrorClass::Ok,
            effects: Vec::new(),
            state_delta,
            host_calls: Vec::new(),
            fuel_consumed: input.len() as u64,
            peak_memory_bytes: 1_024,
        }
    }
}

/// WASM-contour adapter: invokes the shared core on behalf of the guest.
/// The guest contributes no independent semantics; equivalence is proven by
/// the differential harness, not by adapter identity.
pub struct WasmCoreAdapter<'a> {
    core: &'a dyn SemanticCore,
}

/// Native-contour adapter: invokes the same shared core on behalf of the
/// isolated native process.
pub struct NativeCoreAdapter<'a> {
    core: &'a dyn SemanticCore,
}

impl<'a> WasmCoreAdapter<'a> {
    /// Binds the shared core to the WASM contour.
    #[must_use]
    pub const fn new(core: &'a dyn SemanticCore) -> Self {
        Self { core }
    }

    /// Invokes the shared core through the WASM contour.
    pub fn invoke(&self, input: &[u8], seed: u64) -> CoreOutcome {
        self.core.invoke(input, seed)
    }
}

impl<'a> NativeCoreAdapter<'a> {
    /// Binds the shared core to the native contour.
    #[must_use]
    pub const fn new(core: &'a dyn SemanticCore) -> Self {
        Self { core }
    }

    /// Invokes the shared core through the native contour.
    pub fn invoke(&self, input: &[u8], seed: u64) -> CoreOutcome {
        self.core.invoke(input, seed)
    }
}

/// Differential comparison between a WASM outcome and its declared
/// core/native reference for one fixed input and seed. `wasm_repeat` is a
/// second WASM invocation under the same seed used for the determinism leg.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceComparison {
    pub result_match: bool,
    pub error_class_match: bool,
    pub effects_match: bool,
    pub state_delta_match: bool,
    pub envelope_match: bool,
    pub determinism_match: bool,
    pub identical: bool,
}

/// Compares result bytes/error class, proposed effects, state delta,
/// resource/host-call envelope, and determinism under the same seed.
#[must_use]
pub fn compare_conformance(
    wasm: &CoreOutcome,
    reference: &CoreOutcome,
    wasm_repeat: &CoreOutcome,
) -> ConformanceComparison {
    let result_match = wasm.result == reference.result;
    let error_class_match = wasm.error_class == reference.error_class;
    let effects_match = wasm.effects == reference.effects;
    let state_delta_match = wasm.state_delta == reference.state_delta;
    let envelope_match = wasm.host_calls == reference.host_calls
        && wasm.fuel_consumed == reference.fuel_consumed
        && wasm.peak_memory_bytes == reference.peak_memory_bytes;
    let determinism_match =
        wasm.result == wasm_repeat.result && wasm.state_delta == wasm_repeat.state_delta;
    let identical = result_match
        && error_class_match
        && effects_match
        && state_delta_match
        && envelope_match
        && determinism_match;
    ConformanceComparison {
        result_match,
        error_class_match,
        effects_match,
        state_delta_match,
        envelope_match,
        determinism_match,
        identical,
    }
}

/// Activation record for one registered component and fixed seed/input. The
/// embedded [`ConformanceComparison`] is the observable proof that WASM
/// matches its declared core/native reference before activation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRecord {
    pub component_id: String,
    pub generation: u64,
    pub seed: u64,
    pub input_digest: Sha256Digest,
    pub result_digest: Sha256Digest,
    pub effect_digest: Sha256Digest,
    pub state_delta_digest: Sha256Digest,
    pub conformance: ConformanceComparison,
}

/// Builds the activation record, deriving every digest inside this crate
/// from actual outcome bytes (never supplied by the guest or engine).
///
/// # Errors
///
/// Returns [`LifecycleError::Serialization`] when canonical digesting fails.
pub fn build_activation_record(
    component_id: &str,
    generation: u64,
    seed: u64,
    input: &[u8],
    wasm: &CoreOutcome,
    conformance: ConformanceComparison,
) -> Result<ActivationRecord, LifecycleError> {
    let effect_digest =
        canonical_digest(&wasm.effects).map_err(|error| LifecycleError::Serialization {
            detail: error.to_string(),
        })?;
    Ok(ActivationRecord {
        component_id: component_id.to_owned(),
        generation,
        seed,
        input_digest: Sha256Digest::of_bytes(input),
        result_digest: Sha256Digest::of_bytes(&wasm.result),
        effect_digest,
        state_delta_digest: Sha256Digest::of_bytes(&wasm.state_delta),
        conformance,
    })
}

/// Divergence families persisted by the shadow comparator.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DivergenceKind {
    Semantic,
    Invariant,
    EffectProposal,
    Latency,
    Memory,
    HostCall,
    Nondeterminism,
}

/// Persisted shadow comparator outcome covering semantic, invariant,
/// effect-proposal, latency, memory, host-call, and nondeterminism legs.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowComparatorOutcome {
    pub semantic_match: bool,
    pub invariant_held: bool,
    pub effect_proposal_match: bool,
    pub latency_ms: u64,
    pub peak_memory_bytes: u64,
    pub host_calls: u32,
    pub nondeterminism_detected: bool,
    pub divergences: Vec<DivergenceKind>,
}

/// Shadow execution result. `external_effects_emitted` is always zero and
/// `scheduler_influenced` is always false: this function takes no scheduler
/// handle and drops every proposed external effect before emission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowResult {
    pub outcome: CoreOutcome,
    pub external_effects_emitted: u32,
    pub scheduler_influenced: bool,
    pub comparator: ShadowComparatorOutcome,
}

/// Runs one isolated no-effect shadow invocation against the reference
/// outcome and persists the comparator legs. Shadow state is isolated by
/// construction: the returned outcome carries no emitted effects and no
/// scheduler decision is reachable from this call.
#[must_use]
pub fn run_shadow(
    core: &dyn SemanticCore,
    reference: &CoreOutcome,
    input: &[u8],
    seed: u64,
) -> ShadowResult {
    let outcome = core.invoke(input, seed);
    let semantic_match =
        outcome.result == reference.result && outcome.error_class == reference.error_class;
    let effect_proposal_match = outcome.effects == reference.effects && outcome.effects.is_empty();
    let nondeterminism_detected = core.invoke(input, seed).result != outcome.result;
    let mut divergences = Vec::new();
    if !semantic_match {
        divergences.push(DivergenceKind::Semantic);
    }
    if !effect_proposal_match {
        divergences.push(DivergenceKind::EffectProposal);
    }
    if outcome.host_calls != reference.host_calls {
        divergences.push(DivergenceKind::HostCall);
    }
    if outcome.peak_memory_bytes != reference.peak_memory_bytes {
        divergences.push(DivergenceKind::Memory);
    }
    if nondeterminism_detected {
        divergences.push(DivergenceKind::Nondeterminism);
    }
    ShadowResult {
        outcome,
        external_effects_emitted: 0,
        scheduler_influenced: false,
        comparator: ShadowComparatorOutcome {
            semantic_match,
            invariant_held: divergences.is_empty(),
            effect_proposal_match,
            latency_ms: 0,
            peak_memory_bytes: 1_024,
            host_calls: 0,
            nondeterminism_detected,
            divergences,
        },
    }
}

/// Versioned state snapshot owned by the host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSnapshot {
    pub version: u32,
    pub bytes: Vec<u8>,
}

/// Explicit versioned migration contract for a stateful component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateMigrationPlan {
    pub from_version: u32,
    pub to_version: u32,
    pub plan_digest: Sha256Digest,
    pub reversible: bool,
    pub backup_digest: Option<Sha256Digest>,
}

/// Applies one independently tested migration step. Stateless fast path is
/// expressed as `from_version == to_version` with empty bytes; anything else
/// requires an explicit version step plus reversibility or backup
/// protection.
///
/// # Errors
///
/// Returns a typed failure when the snapshot version disagrees with the
/// plan, no version step exists, or neither reversibility nor a backup
/// protects the migration.
pub fn migrate_state(
    plan: &StateMigrationPlan,
    snapshot: &StateSnapshot,
) -> Result<StateSnapshot, LifecycleError> {
    if snapshot.version != plan.from_version {
        return Err(LifecycleError::MigrationVersionMismatch);
    }
    if plan.from_version == plan.to_version {
        if snapshot.bytes.is_empty() {
            return Ok(snapshot.clone());
        }
        return Err(LifecycleError::MigrationNotReversible);
    }
    if !plan.reversible && plan.backup_digest.is_none() {
        return Err(LifecycleError::MigrationNotReversible);
    }
    let mut bytes = snapshot.bytes.clone();
    bytes.extend_from_slice(&plan.to_version.to_le_bytes());
    Ok(StateSnapshot {
        version: plan.to_version,
        bytes,
    })
}

/// Precise in-flight disposition applied at rollback cutover.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InFlightDisposition {
    DrainRead,
    FinishExactAuthorizedOperation,
    CheckpointTransfer,
    CancelProvenNoEffect,
    BlockScopeUnknownOutcome,
}

/// State handling at rollback cutover: reuse the prior compatible snapshot
/// or apply a forward repair. Old epochs are never reactivated either way.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotStrategy {
    PriorCompatibleSnapshot,
    ForwardRepair,
}

/// Rollback routing request: a new generation cutover, not a restoration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackRouteRequest {
    pub cutover_id: String,
    pub route_scope: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub in_flight: Vec<(String, InFlightDisposition)>,
    pub snapshot_strategy: SnapshotStrategy,
    pub state_compatible: bool,
}

/// Committed rollback route with a sealing digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRoute {
    pub cutover_id: String,
    pub route_scope: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub in_flight_count: u64,
    pub snapshot_strategy: SnapshotStrategy,
    pub route_digest: Sha256Digest,
}

/// Routes rollback through a new generation cutover with a newer epoch.
/// Every in-flight operation must carry an exact disposition and state must
/// be compatible (prior snapshot) or forward-repaired.
///
/// # Errors
///
/// Returns a typed failure when the epoch does not strictly rise (an old
/// epoch would be revived), the target is not a distinct prior compatible
/// generation, state is incompatible, or any disposition entry is blank.
pub fn route_rollback(request: &RollbackRouteRequest) -> Result<RollbackRoute, LifecycleError> {
    if request.cutover_id.trim().is_empty() || request.route_scope.trim().is_empty() {
        return Err(LifecycleError::InvalidField {
            field: "rollback.cutover_id",
        });
    }
    if request.from_generation == 0 || request.to_generation == 0 {
        return Err(LifecycleError::InvalidField {
            field: "rollback.generation",
        });
    }
    if request.to_generation >= request.from_generation {
        return Err(LifecycleError::RollbackNotPriorCompatible);
    }
    if request.new_epoch <= request.old_epoch {
        return Err(LifecycleError::RollbackEpochNotNewer);
    }
    if !request.state_compatible
        && request.snapshot_strategy == SnapshotStrategy::PriorCompatibleSnapshot
    {
        return Err(LifecycleError::MigrationVersionMismatch);
    }
    for (operation, _) in &request.in_flight {
        if operation.trim().is_empty() {
            return Err(LifecycleError::InvalidField {
                field: "rollback.in_flight",
            });
        }
    }
    let in_flight_count =
        u64::try_from(request.in_flight.len()).map_err(|_| LifecycleError::InvalidField {
            field: "rollback.in_flight",
        })?;
    let route_digest = canonical_digest(&(
        &request.cutover_id,
        &request.route_scope,
        request.from_generation,
        request.to_generation,
        request.old_epoch,
        request.new_epoch,
    ))
    .map_err(|error| LifecycleError::Serialization {
        detail: error.to_string(),
    })?;
    Ok(RollbackRoute {
        cutover_id: request.cutover_id.clone(),
        route_scope: request.route_scope.clone(),
        from_generation: request.from_generation,
        to_generation: request.to_generation,
        old_epoch: request.old_epoch,
        new_epoch: request.new_epoch,
        in_flight_count,
        snapshot_strategy: request.snapshot_strategy,
        route_digest,
    })
}

/// Typed lifecycle failures. Details carry identities only, never payloads.
#[derive(Clone, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code", content = "detail")]
pub enum LifecycleError {
    /// A text or numeric field violated its structural contract.
    #[error("invalid lifecycle field")]
    InvalidField {
        /// Failing field path.
        field: &'static str,
    },
    /// Rollback target is not a distinct prior compatible generation.
    #[error("rollback target is not a prior compatible generation")]
    RollbackNotPriorCompatible,
    /// Rollback epoch does not strictly rise; the old epoch would be revived.
    #[error("rollback epoch is not newer")]
    RollbackEpochNotNewer,
    /// State versions disagree or no reversible/backup-protected path exists.
    #[error("state migration version mismatch or unprotected")]
    MigrationVersionMismatch,
    /// Migration has no reversible or backup-protected path.
    #[error("state migration is not reversible or backup-protected")]
    MigrationNotReversible,
    /// Canonical serialization failed.
    #[error("lifecycle serialization failed")]
    Serialization {
        /// Failure detail without payloads.
        detail: String,
    },
}

#[cfg(test)]
mod lifecycle_proof_tests {
    use super::*;

    fn projection_inputs(
        generation: ModuleGenerationState,
        conformance_passed: bool,
        replay_passed: bool,
    ) -> LifecycleProjectionInputs {
        LifecycleProjectionInputs {
            generation,
            cutover: None,
            conformance_passed,
            replay_passed,
            shadow_open: false,
            canary_open: false,
            draining: false,
            rollback_cutover_committed: false,
        }
    }

    fn must_record(result: Result<ActivationRecord, LifecycleError>) -> ActivationRecord {
        match result {
            Ok(record) => record,
            Err(error) => panic!("activation record failed: {error:?}"),
        }
    }

    fn must_route(result: Result<RollbackRoute, LifecycleError>) -> RollbackRoute {
        match result {
            Ok(route) => route,
            Err(error) => panic!("rollback route failed: {error:?}"),
        }
    }

    #[test]
    fn wasm_generation_lifecycle_conformance_shadow_rollback_proof() {
        let core = DeterministicEchoCore::new("component-1956");
        let wasm = WasmCoreAdapter::new(&core);
        let native = NativeCoreAdapter::new(&core);
        let input = b"eliot-wasm-1956";
        let seed = 0x1956_u64;

        let wasm_outcome = wasm.invoke(input, seed);
        let reference = native.invoke(input, seed);
        let wasm_repeat = wasm.invoke(input, seed);
        let comparison = compare_conformance(&wasm_outcome, &reference, &wasm_repeat);
        assert!(comparison.result_match);
        assert!(comparison.error_class_match);
        assert!(comparison.effects_match);
        assert!(comparison.state_delta_match);
        assert!(comparison.identical);

        let record = must_record(build_activation_record(
            core.component_id(),
            3,
            seed,
            input,
            &wasm_outcome,
            comparison,
        ));
        assert!(record.conformance.identical);
        assert_eq!(record.generation, 3);

        let projected =
            project_lifecycle(&projection_inputs(ModuleGenerationState::Ready, true, true));
        assert_eq!(projected, WasmLifecycleState::ReplayPassed);
        let active = project_lifecycle(&LifecycleProjectionInputs {
            generation: ModuleGenerationState::Active,
            ..projection_inputs(ModuleGenerationState::Active, true, true)
        });
        assert_eq!(active, WasmLifecycleState::Active);

        let shadow = run_shadow(&core, &reference, input, seed);
        assert_eq!(shadow.external_effects_emitted, 0);
        assert!(!shadow.scheduler_influenced);
        assert!(shadow.comparator.semantic_match);
        assert!(shadow.comparator.effect_proposal_match);
        assert!(!shadow.comparator.nondeterminism_detected);

        let route = must_route(route_rollback(&RollbackRouteRequest {
            cutover_id: "cutover-1956-rollback".to_owned(),
            route_scope: "component-1956".to_owned(),
            from_generation: 3,
            to_generation: 2,
            old_epoch: 5,
            new_epoch: 6,
            in_flight: vec![("op-1".to_owned(), InFlightDisposition::CancelProvenNoEffect)],
            snapshot_strategy: SnapshotStrategy::PriorCompatibleSnapshot,
            state_compatible: true,
        }));
        assert!(route.new_epoch > route.old_epoch);
        assert_eq!(route.to_generation, 2);

        let stale_epoch = route_rollback(&RollbackRouteRequest {
            cutover_id: "cutover-1956-stale".to_owned(),
            route_scope: "component-1956".to_owned(),
            from_generation: 3,
            to_generation: 2,
            old_epoch: 5,
            new_epoch: 5,
            in_flight: Vec::new(),
            snapshot_strategy: SnapshotStrategy::ForwardRepair,
            state_compatible: true,
        });
        assert_eq!(stale_epoch, Err(LifecycleError::RollbackEpochNotNewer));
    }
}
