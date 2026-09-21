//! WASM generation lifecycle projection, conformance, shadow, migration,
//! and rollback routing for issue #1956 (I14.19 / I14.14).
//!
//! Every type here is a pure projection over the Kernel-owned canonical
//! machines (`ModuleGeneration` / `GenerationCutoverRecord` from
//! `eliot-runtime-contracts`). Nothing here mints generation authority,
//! admits a contour, writes canonical state, or implements an engine. Guest
//! execution reaches the Host Wasmtime provider only through the real
//! [`ComponentEnginePort`](crate::ComponentEnginePort) boundary: the contour
//! adapters below forward an owner-sealed [`EngineInvocation`] and map the
//! actual [`EngineReport`] into a [`CoreOutcome`]. The semantic core itself
//! stays runtime-independent and is used only as the declared conformance
//! reference; it is never presented as a WASM execution.
//!
//! Resource observations (`fuel_consumed`, `peak_memory_bytes`, `elapsed_ms`,
//! `host_calls`) are carried only when an executor actually observed them.
//! The pure reference core yields explicit unknown, and the differential
//! harness compares envelopes exactly: an unobserved envelope never confirms
//! an observed one. Shadow execution is effect-free by construction (no
//! scheduler handle is taken, external effects are dropped before they can
//! be emitted) and the comparator outcome persists observed legs with
//! explicit unknown where nothing was observed. Rollback proposes a newer
//! routing cutover — never a committed one: the new authority epoch must
//! strictly rise, an old epoch is never reactivated, and only the
//! Kernel-owned cutover receipt commits the route.
//!
//! State migration performs no transform of its own: the component-owned
//! migration handler exports/imports state, and [`migrate_state`] verifies
//! the identity-bound plan envelope before accepting the candidate result.

use std::collections::BTreeMap;

use eliot_runtime_contracts::{GenerationCutoverState, ModuleGenerationState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CapabilityId, ComponentEnginePort, EffectProposal, EngineInvocation, EngineReport,
    EngineTermination, PortError, Sha256Digest, canonical_digest,
};

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
    // Quiescing is drain in progress on the canonical machine
    // (`Quiescing → Drained`), so it projects as draining without further
    // evidence. A degraded generation only drains while its canary is open.
    if inputs.draining || matches!(inputs.generation, ModuleGenerationState::Quiescing) {
        return WasmLifecycleState::Draining;
    }
    if matches!(inputs.generation, ModuleGenerationState::Degraded) && inputs.canary_open {
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
///
/// `result`, `error_class`, `effects`, `state_delta`, and `host_calls` carry
/// the invocation's semantic content. `fuel_consumed`, `peak_memory_bytes`,
/// and `elapsed_ms` carry executor observations only when an executor
/// actually measured them (`None` is explicit unknown, never zero). The pure
/// reference core yields unknown for all three; engine-backed outcomes carry
/// the exact [`EngineReport`] observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreOutcome {
    pub result: Vec<u8>,
    pub error_class: ErrorClass,
    pub effects: Vec<EffectProposal>,
    pub state_delta: Vec<u8>,
    pub host_calls: Option<Vec<CapabilityId>>,
    pub fuel_consumed: Option<u64>,
    pub peak_memory_bytes: Option<u64>,
    pub elapsed_ms: Option<u64>,
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
/// across contours by construction. Pure stateless logic observes no state
/// change, so the state delta is explicitly empty: no guest through the
/// current provider can report one either, and a digest convention here
/// would manufacture a mismatch against real execution.
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
        // Pure logic observes no resources and touches no state: fuel,
        // memory, elapsed time, and host calls stay explicitly unknown,
        // and the state delta is empty. Analytical bounds, if any, belong
        // to the invocation limits, not to this outcome.
        CoreOutcome {
            result,
            error_class: ErrorClass::Ok,
            effects: Vec::new(),
            state_delta: Vec::new(),
            host_calls: None,
            fuel_consumed: None,
            peak_memory_bytes: None,
            elapsed_ms: None,
        }
    }
}

/// Maps one actual engine report into the shared outcome shape.
///
/// Termination maps exactly: completion is `Ok`; cancellation, deadline,
/// partial, and post-commit-unknown outcomes are `Unknown` (their effect is
/// unresolved); every bounded trap, limit, or denial is `Rejected`.
/// Observations ride through verbatim; nothing is synthesized.
#[must_use]
pub fn core_outcome_from_report(report: &EngineReport) -> CoreOutcome {
    let error_class = match report.termination {
        EngineTermination::Completed => ErrorClass::Ok,
        EngineTermination::Cancelled
        | EngineTermination::Deadline
        | EngineTermination::EpochDeadline
        | EngineTermination::Partial
        | EngineTermination::PostCommitUnknown => ErrorClass::Unknown,
        EngineTermination::Trap(_)
        | EngineTermination::OutputLimit
        | EngineTermination::HostCallLimit
        | EngineTermination::FuelExhausted
        | EngineTermination::MemoryLimit
        | EngineTermination::TableLimit
        | EngineTermination::InstanceLimit
        | EngineTermination::StackLimit
        | EngineTermination::ArtifactAccessDenied => ErrorClass::Rejected,
    };
    CoreOutcome {
        result: report.output.clone(),
        error_class,
        effects: report.proposed_effects.clone(),
        state_delta: report.observed_state_delta.clone(),
        host_calls: Some(report.host_calls.clone()),
        fuel_consumed: Some(report.usage.fuel_consumed),
        peak_memory_bytes: report.usage.peak_memory_bytes,
        elapsed_ms: Some(report.usage.elapsed_ms),
    }
}

/// Maps an engine-boundary failure into an outcome with no observations.
/// Denial is a bounded rejection; unavailability and unknown outcome stay
/// exactly what they are. Such outcomes can never satisfy conformance
/// acceptance, which requires `Ok` legs derived from real outputs.
#[must_use]
fn core_outcome_from_port_error(error: PortError) -> CoreOutcome {
    let error_class = match error {
        PortError::Denied => ErrorClass::Rejected,
        PortError::Unavailable => ErrorClass::Unavailable,
        PortError::UnknownOutcome => ErrorClass::Unknown,
    };
    CoreOutcome {
        result: Vec::new(),
        error_class,
        effects: Vec::new(),
        state_delta: Vec::new(),
        host_calls: None,
        fuel_consumed: None,
        peak_memory_bytes: None,
        elapsed_ms: None,
    }
}

fn invoke_via_engine(
    engine: &mut dyn ComponentEnginePort,
    invocation: &EngineInvocation,
) -> CoreOutcome {
    match engine.invoke(invocation) {
        Ok(report) => core_outcome_from_report(&report),
        Err(error) => core_outcome_from_port_error(error),
    }
}

/// WASM-contour adapter: forwards the owner-sealed invocation through the
/// real engine boundary to the Host Wasmtime provider and maps the actual
/// report. The contour is determined by the bound engine provider, which is
/// a composition fact this crate never decides. The guest contributes no
/// independent semantics; equivalence is proven by the differential harness
/// over real reports, not by adapter identity.
pub struct WasmCoreAdapter;

/// Native-contour adapter: forwards the owner-sealed invocation through the
/// real engine boundary to the governed native-process provider and maps the
/// actual report. Same neutral path as the WASM contour; only the bound
/// provider differs, which remains a composition fact.
pub struct NativeCoreAdapter;

impl WasmCoreAdapter {
    /// Invokes the Host Wasmtime provider through the real engine boundary.
    #[must_use]
    pub fn invoke(
        engine: &mut dyn ComponentEnginePort,
        invocation: &EngineInvocation,
    ) -> CoreOutcome {
        invoke_via_engine(engine, invocation)
    }
}

impl NativeCoreAdapter {
    /// Invokes the governed native provider through the real engine boundary.
    #[must_use]
    pub fn invoke(
        engine: &mut dyn ComponentEnginePort,
        invocation: &EngineInvocation,
    ) -> CoreOutcome {
        invoke_via_engine(engine, invocation)
    }
}

/// Differential comparison between a contour outcome and its declared
/// core/native reference for one fixed input and seed. `wasm_repeat` is a
/// second contour invocation under the same seed used for the determinism
/// leg. `identical` is derived by [`compare_conformance`] and readable
/// through [`ConformanceComparison::identical`]; it is not settable, so a
/// forged comparison cannot be constructed to claim acceptance.
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
    identical: bool,
}

impl ConformanceComparison {
    /// Reports whether every compared leg holds. Derived, never assigned.
    #[must_use]
    pub const fn identical(&self) -> bool {
        self.identical
    }
}

/// Compares result bytes/error class, proposed effects, state delta,
/// resource/host-call envelope, and determinism under the same seed.
/// The envelope leg compares observed resource bindings exactly: an
/// unobserved envelope (`None`) never confirms an observed one, and elapsed
/// time is carried as evidence but excluded from the leg (timing varies
/// run to run; determinism is proven over result and state delta).
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
/// from actual outcome bytes (never supplied by the guest or engine) and
/// deriving acceptance from a fresh comparison of the real outputs.
///
/// The caller supplies the contour outcome, its declared reference, and a
/// same-seed repeat; this function runs [`compare_conformance`] itself and
/// persists the computed comparison. There is no comparison parameter to
/// forge: acceptance requires the result, error-class, effects, and
/// state-delta legs to hold on the actual outputs, otherwise
/// [`LifecycleError::ConformanceNotSatisfied`] is returned and no record
/// exists.
///
/// # Errors
///
/// Returns [`LifecycleError::ConformanceNotSatisfied`] when any acceptance
/// leg fails, [`LifecycleError::InvalidField`] for a blank component
/// identity, or [`LifecycleError::Serialization`] when canonical digesting
/// fails.
pub fn build_activation_record(
    component_id: &str,
    generation: u64,
    seed: u64,
    input: &[u8],
    wasm: &CoreOutcome,
    reference: &CoreOutcome,
    wasm_repeat: &CoreOutcome,
) -> Result<ActivationRecord, LifecycleError> {
    if component_id.trim().is_empty() {
        return Err(LifecycleError::InvalidField {
            field: "activation.component_id",
        });
    }
    let conformance = compare_conformance(wasm, reference, wasm_repeat);
    if !(conformance.result_match
        && conformance.error_class_match
        && conformance.effects_match
        && conformance.state_delta_match)
    {
        return Err(LifecycleError::ConformanceNotSatisfied);
    }
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
/// Measurement fields are `Some` only when the reconciled contour outcome
/// carried an executor observation; `None` is explicit unknown, never zero.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowComparatorOutcome {
    pub semantic_match: bool,
    pub invariant_held: bool,
    pub effect_proposal_match: bool,
    pub latency_ms: Option<u64>,
    pub peak_memory_bytes: Option<u64>,
    pub host_calls: Option<u32>,
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

/// Reconciles one isolated no-effect shadow invocation against the
/// reference outcome and persists the comparator legs.
///
/// The contour outcomes are produced by the caller through the real engine
/// boundary (the shadow invocation itself, with its contour, effect
/// dropping, and scheduler isolation, belongs to the executing composition,
/// not to this pure function). This function only compares: semantic,
/// effect-proposal, host-call, and memory legs over the carried
/// observations, plus a determinism leg between the two same-seed contour
/// outcomes. `host_calls` count is derived from the carried identity list
/// when the executor observed it, and stays unknown otherwise. Shadow state
/// remains isolated by construction: reconciled outcomes carry no emitted
/// effects and no scheduler decision is reachable from this call.
#[must_use]
pub fn reconcile_shadow(
    wasm: &CoreOutcome,
    wasm_repeat: &CoreOutcome,
    reference: &CoreOutcome,
) -> ShadowResult {
    let semantic_match =
        wasm.result == reference.result && wasm.error_class == reference.error_class;
    // Effect proposals are compared, not forbidden: emission is what the
    // executing shadow drops (always zero below). Identical proposals on
    // both contours match.
    let effect_proposal_match = wasm.effects == reference.effects;
    let nondeterminism_detected =
        wasm.result != wasm_repeat.result || wasm.state_delta != wasm_repeat.state_delta;
    let host_calls = wasm
        .host_calls
        .as_ref()
        .and_then(|calls| u32::try_from(calls.len()).ok());
    let mut divergences = Vec::new();
    if !semantic_match {
        divergences.push(DivergenceKind::Semantic);
    }
    if !effect_proposal_match {
        divergences.push(DivergenceKind::EffectProposal);
    }
    if wasm.host_calls != reference.host_calls {
        divergences.push(DivergenceKind::HostCall);
    }
    if wasm.peak_memory_bytes != reference.peak_memory_bytes {
        divergences.push(DivergenceKind::Memory);
    }
    if nondeterminism_detected {
        divergences.push(DivergenceKind::Nondeterminism);
    }
    ShadowResult {
        outcome: wasm.clone(),
        external_effects_emitted: 0,
        scheduler_influenced: false,
        comparator: ShadowComparatorOutcome {
            semantic_match,
            invariant_held: divergences.is_empty(),
            effect_proposal_match,
            latency_ms: wasm.elapsed_ms,
            peak_memory_bytes: wasm.peak_memory_bytes,
            host_calls,
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
///
/// The component-owned migration handler exports/imports state; this plan
/// only binds the migration's identity. `plan_digest` must equal the
/// canonical digest over `(from_version, to_version, handler_id)`, so a plan
/// cannot silently change handler or versions after issue. `reversible` or a
/// `backup_digest` must protect every version step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateMigrationPlan {
    pub from_version: u32,
    pub to_version: u32,
    pub handler_id: String,
    pub plan_digest: Sha256Digest,
    pub reversible: bool,
    pub backup_digest: Option<Sha256Digest>,
}

/// Verifies one independently performed migration step and accepts the
/// handler-produced candidate result. This function performs no transform of
/// its own: the export/import bytes come from the component-owned handler,
/// and acceptance checks the identity-bound plan envelope (handler binding,
/// version step, digest binding) plus reversibility or backup protection.
/// Stateless fast path is expressed as `from_version == to_version` with
/// empty bytes and an identical candidate; anything else requires an
/// explicit version step plus protection.
///
/// # Errors
///
/// Returns a typed failure when the handler identity is blank, the plan
/// digest does not bind the declared versions and handler, the snapshot
/// version disagrees with the plan, the candidate version disagrees with
/// the target, or neither reversibility nor a backup protects the step.
pub fn migrate_state(
    plan: &StateMigrationPlan,
    snapshot: &StateSnapshot,
    migrated: &StateSnapshot,
) -> Result<StateSnapshot, LifecycleError> {
    if plan.handler_id.trim().is_empty() {
        return Err(LifecycleError::InvalidField {
            field: "migration.handler_id",
        });
    }
    if snapshot.version != plan.from_version {
        return Err(LifecycleError::MigrationVersionMismatch);
    }
    let bound = canonical_digest(&(plan.from_version, plan.to_version, plan.handler_id.as_str()))
        .map_err(|error| LifecycleError::Serialization {
        detail: error.to_string(),
    })?;
    if bound != plan.plan_digest {
        return Err(LifecycleError::InvalidField {
            field: "migration.plan_digest",
        });
    }
    if plan.from_version == plan.to_version {
        if snapshot.bytes.is_empty()
            && migrated.version == plan.from_version
            && migrated.bytes == snapshot.bytes
        {
            return Ok(migrated.clone());
        }
        return Err(LifecycleError::MigrationNotReversible);
    }
    if migrated.version != plan.to_version {
        return Err(LifecycleError::MigrationVersionMismatch);
    }
    if !plan.reversible && plan.backup_digest.is_none() {
        return Err(LifecycleError::MigrationNotReversible);
    }
    Ok(migrated.clone())
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

/// Rollback routing proposal: a new generation cutover, not a restoration.
///
/// This value is PROPOSED, never committed. Committing the route —
/// persisting the `GenerationCutoverRecord` in ORS, running the cutover
/// transition, and emitting the `GenerationCutoverReceipt` — is owned by the
/// Kernel cutover path (`eliot-runtime-contracts::{GenerationCutoverRecord,
/// GenerationCutoverReceipt}` validation; Ramanujan-owned serving lane).
/// Only a validated receipt may set `rollback_cutover_committed` on the
/// projection inputs. Treating this proposal as committed would revive the
/// exact defect this module exists to prevent.
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

/// Proposed rollback route with a sealing digest. Unpersisted by
/// construction: no field here claims commitment, linearization, or receipt.
/// See [`RollbackRouteRequest`] for the commit boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRouteProposal {
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

/// Proposes rollback routing through a new generation cutover with a newer
/// epoch. Every in-flight operation must carry an exact disposition, one
/// operation identity admits exactly one disposition, and state must be
/// compatible (prior snapshot) or forward-repaired. The sealing digest
/// binds the cutover/route/generation/epoch identities together with the
/// committed in-flight dispositions, snapshot strategy, and compatibility
/// flag, so the sealed decision cannot silently change after commit.
///
/// # Errors
///
/// Returns a typed failure when the epoch does not strictly rise (an old
/// epoch would be revived), the target is not a distinct prior compatible
/// generation, state is incompatible, any disposition entry is blank, or one
/// operation identity carries conflicting dispositions.
pub fn route_rollback(
    request: &RollbackRouteRequest,
) -> Result<RollbackRouteProposal, LifecycleError> {
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
    let mut dispositions: BTreeMap<&str, InFlightDisposition> = BTreeMap::new();
    for (operation, disposition) in &request.in_flight {
        if operation.trim().is_empty() {
            return Err(LifecycleError::InvalidField {
                field: "rollback.in_flight",
            });
        }
        match dispositions.insert(operation.as_str(), *disposition) {
            Some(previous) if previous != *disposition => {
                return Err(LifecycleError::RollbackInFlightConflict);
            }
            _ => {}
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
        &request.in_flight,
        request.snapshot_strategy,
        request.state_compatible,
    ))
    .map_err(|error| LifecycleError::Serialization {
        detail: error.to_string(),
    })?;
    Ok(RollbackRouteProposal {
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
    /// One in-flight operation identity carries conflicting dispositions.
    #[error("rollback in-flight operation carries conflicting dispositions")]
    RollbackInFlightConflict,
    /// The contour/reference comparison does not satisfy acceptance.
    #[error("wasm conformance legs do not hold")]
    ConformanceNotSatisfied,
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
    use std::collections::BTreeSet;

    use super::{
        BTreeMap, CapabilityId, ComponentEnginePort, CoreOutcome, DeterministicEchoCore,
        DivergenceKind, EffectProposal, EngineInvocation, EngineReport, EngineTermination,
        ErrorClass, InFlightDisposition, LifecycleError, LifecycleProjectionInputs,
        ModuleGenerationState, NativeCoreAdapter, PortError, RollbackRouteRequest, SemanticCore,
        Sha256Digest, SnapshotStrategy, StateMigrationPlan, StateSnapshot, WasmCoreAdapter,
        WasmLifecycleState, build_activation_record, canonical_digest, compare_conformance,
        migrate_state, project_lifecycle, reconcile_shadow, route_rollback,
    };
    use eliot_observation_contracts::ObservationScope;
    use eliot_process::{
        ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
        EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation, ImageId, JobId,
        KernelDispatchKey, OperationId, PermitIssuance, PhysicalProcessBinding, ProcessHealth,
        ProcessHealthStatus, ProcessId, ProcessIntent, ProcessRequest, ProcessStartReceipt,
        ProcessState, ProcessTreeId, ResourceLimits as ProcessLimits, SessionId,
        SuspendedProcessIdentity,
    };
    use eliot_runtime_contracts::{ModuleGeneration, RuntimeLease};
    use eliot_security_contracts::{PrivacyClass, SourceAssurance};
    use serde_json::json;

    use super::*;
    use crate::{
        ArtifactAccessLimits, CancellationPolicy, ComponentManifest, EngineBinding, EngineUsage,
        EpochPolicy, ExecutionContour, InvocationId, InvocationLimits, OwnerId, ProcessBinding,
        Revision, WorkUnitId,
    };

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_COMPONENT: &str = "component-1956";
    const TEST_INPUT: &[u8] = b"lc-wasm-1956";
    const TEST_SEED: u64 = 0x1956;

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("fixture result failed: {error:?}"),
        }
    }

    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::of_bytes(&[character as u8])
    }

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

    fn must_route(result: Result<RollbackRouteProposal, LifecycleError>) -> RollbackRouteProposal {
        match result {
            Ok(route) => route,
            Err(error) => panic!("rollback route failed: {error:?}"),
        }
    }

    fn must_id(value: Result<CapabilityId, crate::RuntimeError>) -> CapabilityId {
        match value {
            Ok(id) => id,
            Err(error) => panic!("capability id failed: {error:?}"),
        }
    }

    fn engine_binding() -> EngineBinding {
        EngineBinding {
            implementation_id: "engine.test.v1".to_owned(),
            exact_version: "1.2.3".to_owned(),
            engine_artifact_digest: digest('8'),
            engine_configuration_digest: digest('9'),
            wit_interface_digest: digest('b'),
        }
    }

    fn manifest() -> ComponentManifest {
        ComponentManifest {
            component_id: must_id(CapabilityId::new(TEST_COMPONENT)),
            world: must_id(CapabilityId::new("eliot:test/world")),
            wit_version: "1.0.0".to_owned(),
            guest_target: crate::DEFAULT_GUEST_TARGET.to_owned(),
            artifact_digest: digest('a'),
            interface_digest: digest('b'),
            source_digest: digest('c'),
            configuration_digest: digest('d'),
            state_contract_digest: digest('e'),
            imports: BTreeSet::from([must_id(CapabilityId::new("log"))]),
            exports: BTreeSet::from([must_id(CapabilityId::new("run"))]),
            admitted_privacy_classes: vec![PrivacyClass::Internal],
            required_verifier: "verifier:a12".to_owned(),
            engine: engine_binding(),
        }
    }

    fn generation_fixture() -> ModuleGeneration {
        must(serde_json::from_value(json!({
            "module_id": TEST_COMPONENT,
            "generation": 3,
            "artifact_id": "a".repeat(64),
            "state": "READY",
            "health": {
                "liveness": "HEALTHY", "readiness": "HEALTHY",
                "freshness": "HEALTHY", "compatibility": "HEALTHY",
                "integrity": "HEALTHY", "capacity": "HEALTHY"
            },
            "state_fence": {
                "authority_epoch": {"lineage_id": TEST_LINEAGE, "sequence": 5},
                "resource_generation": 3,
                "task_revision": 1, "policy_revision": 1,
                "integration_revision": null
            }
        })))
    }

    fn lease_fixture() -> RuntimeLease {
        must(serde_json::from_value(json!({
            "lease_id": "lease-1956", "scope_ref": "scope-1956",
            "authority_epoch": {"lineage_id": TEST_LINEAGE, "sequence": 5},
            "state_fence": {
                "authority_epoch": {"lineage_id": TEST_LINEAGE, "sequence": 5},
                "resource_generation": 3,
                "task_revision": 1, "policy_revision": 1,
                "integration_revision": null
            },
            "state": "ACTIVE"
        })))
    }

    fn work_scope_fixture() -> ObservationScope {
        must(serde_json::from_value(json!({
            "work_scope": "scope-1956", "task_ref": "task-1956",
            "attempt_ref": "work-1956", "module_or_route_ref": TEST_COMPONENT
        })))
    }

    fn assurance_fixture() -> SourceAssurance {
        must(serde_json::from_value(json!({
            "source_ref": "source-1956", "provenance_ref": "provenance-1956",
            "integrity": "VERIFIED", "freshness": "CURRENT",
            "competence": "DOMAIN_VERIFIED", "independence": "INDEPENDENT",
            "privacy_class": "INTERNAL", "instruction_taint": "DATA_ONLY",
            "allowed_epistemic_use": ["VERIFICATION_INPUT"],
            "allowed_effects": ["NO_EXTERNAL_EFFECT"],
            "required_verifier": "verifier:a12", "quarantine": "NONE",
            "state_fence": {
                "authority_epoch": {"lineage_id": TEST_LINEAGE, "sequence": 5},
                "resource_generation": 3,
                "task_revision": 1, "policy_revision": 1,
                "integration_revision": null
            }
        })))
    }

    fn limits_fixture() -> InvocationLimits {
        InvocationLimits {
            max_input_bytes: 128,
            max_output_bytes: 128,
            max_host_calls: 4,
            max_fuel: 1_000,
            max_memory_bytes: 65_536,
            max_table_elements: 64,
            max_instances: 2,
            max_stack_bytes: 8_192,
            wall_deadline_ms: 500,
            epoch: EpochPolicy {
                deadline_ticks: 50,
                cancellation: CancellationPolicy::EpochAndFuel,
            },
            artifact_access: ArtifactAccessLimits {
                allowed_digests: BTreeSet::from([digest('a')]),
                max_reads: 2,
                max_bytes: 1_024,
            },
        }
    }

    fn process_authority() -> DispatchPermitAuthority {
        DispatchPermitAuthority::activate(
            must(DispatchAuthorityId::new("wasm-lifecycle-authority")),
            must(KernelDispatchKey::from_secret_bytes([0x6b; 32])),
        )
    }

    fn revision_heads() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("authority".to_owned(), "a".repeat(64)),
            ("state".to_owned(), "b".repeat(64)),
        ])
    }

    /// Builds the P-03-bound process artifacts for one sealed invocation,
    /// mirroring the owner admission path: intent, permit issuance, observed
    /// resume, receipt. Values are internally consistent fixtures, never
    /// production authority.
    fn process_artifacts(
        lease: &RuntimeLease,
        limits: &InvocationLimits,
    ) -> (ProcessBinding, ProcessStartReceipt) {
        let mut authority = process_authority();
        let generation = must(Generation::new(3));
        let intent = must(ProcessIntent::new(
            must(OperationId::new("lc-op-1956")),
            must(ProcessTreeId::new("scope-1956")),
            must(JobId::new("job-1956")),
            must(ImageId::new("image-1956")),
            must(SessionId::new("session-1956")),
            generation,
            "eliot-wasm-host.exe",
            "e".repeat(64),
            Vec::new(),
            "C:\\eliot\\runtime",
            must(EnvironmentProjection::new(
                BTreeMap::new(),
                Vec::new(),
                EnvironmentInheritance::None,
            )),
            must(ProcessLimits::new(
                limits.wall_deadline_ms,
                None,
                Some(limits.max_memory_bytes),
                limits.max_output_bytes,
                limits.max_output_bytes,
                0,
            )),
        ));
        let fence = must(FencingToken::new(
            lease.state_fence.authority_epoch.clone(),
            generation,
            "fence-1956",
        ));
        let permit = must(authority.issue(
            &intent,
            must(PermitIssuance::new(
                must(ActionLeaseRef::new("process-lease-1956")),
                fence,
                revision_heads(),
                100,
                10_000,
                "nonce-1956".to_owned(),
            )),
        ));
        let request = must(ProcessRequest::new(intent, permit));
        let observed = must(SuspendedProcessIdentity::new(
            must(ProcessId::new("process-lc-op-1956")),
            request.process_tree_id().clone(),
            request.job_id().clone(),
            request.image_id().clone(),
            request.session_id().clone(),
            request.generation(),
            must(PhysicalProcessBinding::new(
                4242,
                11,
                request.executable(),
                "Local\\Eliot-Wasm-Test",
            )),
            120,
            request.executable_sha256(),
        ));
        let clock = must(serde_json::from_value(json!({
            "valid_time_ms": 150,
            "known_time_ms": 150,
            "transaction_sequence": null,
            "monotonic_ns": 1
        })));
        let context = must(DispatchValidationContext::new(
            clock,
            request.fence().clone(),
            request.fence().authority_epoch().clone(),
            revision_heads(),
            1,
        ));
        let binding = ProcessBinding::from_request(&request);
        let validated = must(authority.validate_and_consume(request, observed, &context));
        let mut process = ProcessState::from_validated(&validated);
        must(process.mark_resumed(
            151,
            must(ProcessHealth::new(
                ProcessHealthStatus::Healthy,
                true,
                151,
                None,
            )),
        ));
        let receipt = must(ProcessStartReceipt::new(&process));
        (binding, receipt)
    }

    fn sealed_invocation(input: &[u8], seed: u64) -> EngineInvocation {
        let manifest_value = manifest();
        let lease = lease_fixture();
        let limits = limits_fixture();
        let (process_binding, process_start_receipt) = process_artifacts(&lease, &limits);
        EngineInvocation {
            invocation_id: must(InvocationId::new("lc-invoke-1956")),
            request_digest: Sha256Digest::of_bytes(input),
            component_id: must_id(CapabilityId::new(TEST_COMPONENT)),
            contour: ExecutionContour::Shadow,
            manifest: manifest_value.clone(),
            imports: manifest_value.imports.clone(),
            exports: manifest_value.exports.clone(),
            allowed_host_calls: BTreeSet::new(),
            allowed_effect_proposals: BTreeSet::new(),
            generation: generation_fixture(),
            lease: lease.clone(),
            owner: must(OwnerId::new("owner-1956")),
            work_unit: must(WorkUnitId::new("work-1956")),
            work_scope: work_scope_fixture(),
            authority_revision: must(Revision::new(1)),
            lifecycle_revision: must(Revision::new(1)),
            source_assurance: assurance_fixture(),
            source_verification_revision: must(Revision::new(1)),
            promotion_verification_revision: must(Revision::new(1)),
            conformance_corpus_digest: digest('f'),
            governor_resolution_receipt_digest: digest('0'),
            authority_resolution_receipt_digest: digest('1'),
            source_verification_receipt_digest: digest('2'),
            promotion_verification_receipt_digest: digest('3'),
            state_contract_digest: manifest_value.state_contract_digest.clone(),
            limits,
            input: input.to_vec(),
            deterministic_seed: seed,
            process_binding,
            process_start_receipt,
        }
    }

    /// Fake engine provider standing in for the Host Wasmtime implementation
    /// at the real [`ComponentEnginePort`] boundary. It returns the fixed
    /// report the test arms it with; the adapter path, report mapping, and
    /// leg verification under test are real.
    struct FakeEngine {
        binding: EngineBinding,
        report: EngineReport,
    }

    impl FakeEngine {
        fn report_for(invocation: &EngineInvocation, reference: &CoreOutcome) -> Self {
            let usage = EngineUsage {
                attempted_output_bytes: u64::try_from(reference.result.len()).unwrap_or(u64::MAX),
                output_bytes: u64::try_from(reference.result.len()).unwrap_or(u64::MAX),
                host_calls: 0,
                fuel_consumed: 42,
                peak_memory_bytes: Some(2_048),
                table_elements: Some(1),
                instances: 1,
                stack_bytes: Some(1_024),
                enforced_stack_limit_bytes: None,
                elapsed_ms: 9,
                effective_epoch_policy: invocation.limits.epoch,
                epoch_ticks: Some(3),
                artifact_reads: 1,
                artifact_bytes: 64,
                accessed_artifact_digests: vec![invocation.manifest.artifact_digest.clone()],
            };
            Self {
                binding: invocation.manifest.engine.clone(),
                report: EngineReport {
                    request_digest: invocation.request_digest.clone(),
                    termination: EngineTermination::Completed,
                    usage,
                    output: reference.result.clone(),
                    host_calls: Vec::new(),
                    proposed_effects: reference.effects.clone(),
                    observed_state_delta: reference.state_delta.clone(),
                    post_commit_known: true,
                },
            }
        }
    }

    impl ComponentEnginePort for FakeEngine {
        fn binding(&self) -> &EngineBinding {
            &self.binding
        }

        fn invoke(&mut self, _invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
            Ok(self.report.clone())
        }

        fn reconcile(&mut self, _invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
            Ok(self.report.clone())
        }
    }

    struct DenyingEngine {
        error: PortError,
    }

    impl ComponentEnginePort for DenyingEngine {
        fn binding(&self) -> &EngineBinding {
            panic!("denying engine has no binding");
        }

        fn invoke(&mut self, _invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
            Err(self.error)
        }

        fn reconcile(&mut self, _invocation: &EngineInvocation) -> Result<EngineReport, PortError> {
            Err(self.error)
        }
    }

    /// Backend that disagrees with the reference core on result bytes.
    struct DivergentCore;

    impl SemanticCore for DivergentCore {
        fn invoke(&self, input: &[u8], _seed: u64) -> CoreOutcome {
            let mut result = input.to_vec();
            result.push(0xFF);
            CoreOutcome {
                result,
                error_class: ErrorClass::Ok,
                effects: Vec::new(),
                state_delta: Vec::new(),
                host_calls: None,
                fuel_consumed: None,
                peak_memory_bytes: None,
                elapsed_ms: None,
            }
        }
    }

    /// Backend proposing identical non-empty effects on every invocation.
    struct ProposingCore;

    impl SemanticCore for ProposingCore {
        fn invoke(&self, input: &[u8], seed: u64) -> CoreOutcome {
            let _ = (input, seed);
            CoreOutcome {
                result: vec![0xA5],
                error_class: ErrorClass::Ok,
                effects: vec![EffectProposal {
                    effect_kind: must_id(CapabilityId::new("log")),
                    payload_digest: Sha256Digest::of_bytes(b"proposal"),
                }],
                state_delta: vec![0x5A],
                host_calls: None,
                fuel_consumed: None,
                peak_memory_bytes: None,
                elapsed_ms: None,
            }
        }
    }

    #[test]
    fn wasm_engine_path_conformance_shadow_rollback_proof() {
        let reference = DeterministicEchoCore::new(TEST_COMPONENT).invoke(TEST_INPUT, TEST_SEED);
        let invocation = sealed_invocation(TEST_INPUT, TEST_SEED);
        let mut engine = FakeEngine::report_for(&invocation, &reference);

        // The contour outcome travels the real engine boundary: the fake
        // stands in for the Host Wasmtime provider behind
        // `ComponentEnginePort::invoke`, exactly the I2.20 fake-port seam.
        let wasm = WasmCoreAdapter::invoke(&mut engine, &invocation);
        let wasm_repeat = WasmCoreAdapter::invoke(&mut engine, &invocation);
        assert_eq!(wasm.error_class, ErrorClass::Ok);
        assert_eq!(wasm.result, reference.result);
        // Engine-observed resources ride through verbatim; the pure
        // reference core yields explicit unknown for all three.
        assert_eq!(wasm.fuel_consumed, Some(42));
        assert_eq!(wasm.peak_memory_bytes, Some(2_048));
        assert_eq!(wasm.elapsed_ms, Some(9));
        assert_eq!(reference.fuel_consumed, None);
        assert_eq!(reference.peak_memory_bytes, None);

        let comparison = compare_conformance(&wasm, &reference, &wasm_repeat);
        assert!(comparison.result_match);
        assert!(comparison.error_class_match);
        assert!(comparison.effects_match);
        assert!(comparison.state_delta_match);
        assert!(comparison.determinism_match);
        // Honest non-green: the engine-observed envelope cannot confirm the
        // unobserved reference envelope, so overall identical stays false
        // while every acceptance leg holds.
        assert!(!comparison.envelope_match);
        assert!(!comparison.identical());

        // Acceptance derives from the real outputs inside the builder: the
        // record carries the computed comparison, and forged booleans have
        // no parameter to enter through.
        let record = match build_activation_record(
            TEST_COMPONENT,
            3,
            TEST_SEED,
            TEST_INPUT,
            &wasm,
            &reference,
            &wasm_repeat,
        ) {
            Ok(record) => record,
            Err(error) => panic!("activation record failed: {error:?}"),
        };
        assert!(record.conformance.result_match);
        assert!(!record.conformance.identical());
        assert_eq!(record.generation, 3);

        let projected =
            project_lifecycle(&projection_inputs(ModuleGenerationState::Ready, true, true));
        assert_eq!(projected, WasmLifecycleState::ReplayPassed);
        let active = project_lifecycle(&LifecycleProjectionInputs {
            generation: ModuleGenerationState::Active,
            ..projection_inputs(ModuleGenerationState::Active, true, true)
        });
        assert_eq!(active, WasmLifecycleState::Active);

        // Shadow reconciliation over the engine-backed outcomes: no effect
        // emitted, no scheduler influence; envelope legs truthfully record
        // the observed-vs-unknown divergence.
        let shadow = reconcile_shadow(&wasm, &wasm_repeat, &reference);
        assert_eq!(shadow.external_effects_emitted, 0);
        assert!(!shadow.scheduler_influenced);
        assert!(shadow.comparator.semantic_match);
        assert!(shadow.comparator.effect_proposal_match);
        assert!(!shadow.comparator.nondeterminism_detected);
        assert_eq!(
            shadow.comparator.divergences,
            vec![DivergenceKind::HostCall, DivergenceKind::Memory]
        );
        assert_eq!(shadow.comparator.latency_ms, Some(9));
        assert_eq!(shadow.comparator.peak_memory_bytes, Some(2_048));

        let route = must_route(route_rollback(&RollbackRouteRequest {
            cutover_id: "cutover-1956-rollback".to_owned(),
            route_scope: TEST_COMPONENT.to_owned(),
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
            route_scope: TEST_COMPONENT.to_owned(),
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

    #[test]
    fn divergent_backend_is_detected_not_adopted() {
        let reference = DeterministicEchoCore::new(TEST_COMPONENT).invoke(TEST_INPUT, TEST_SEED);
        let divergent = DivergentCore.invoke(TEST_INPUT, TEST_SEED);
        let repeat = DivergentCore.invoke(TEST_INPUT, TEST_SEED);
        let comparison = compare_conformance(&divergent, &reference, &repeat);
        assert!(!comparison.result_match);
        assert!(!comparison.identical());

        // Forged acceptance is structurally impossible: the gate recomputes
        // from real outputs and refuses the divergent pair.
        assert_eq!(
            build_activation_record(
                TEST_COMPONENT,
                3,
                TEST_SEED,
                TEST_INPUT,
                &divergent,
                &reference,
                &repeat,
            ),
            Err(LifecycleError::ConformanceNotSatisfied)
        );
        assert_eq!(
            build_activation_record(
                "", 3, TEST_SEED, TEST_INPUT, &reference, &reference, &reference,
            ),
            Err(LifecycleError::InvalidField {
                field: "activation.component_id"
            })
        );

        let shadow = reconcile_shadow(&divergent, &repeat, &reference);
        assert_eq!(shadow.external_effects_emitted, 0);
        assert!(!shadow.scheduler_influenced);
        assert!(!shadow.comparator.semantic_match);
        assert!(!shadow.comparator.invariant_held);
        assert_eq!(
            shadow.comparator.divergences,
            vec![DivergenceKind::Semantic]
        );
    }

    #[test]
    fn identical_effect_proposals_match_without_being_empty() {
        let core = ProposingCore;
        let first = core.invoke(b"input", 7);
        let reference = core.invoke(b"input", 7);
        let repeat = core.invoke(b"input", 7);
        let comparison = compare_conformance(&first, &reference, &repeat);
        assert!(comparison.effects_match);
        assert!(comparison.identical());

        let shadow = reconcile_shadow(&first, &repeat, &reference);
        assert!(shadow.comparator.effect_proposal_match);
        assert!(
            !shadow
                .comparator
                .divergences
                .contains(&DivergenceKind::EffectProposal)
        );
    }

    #[test]
    fn termination_and_port_errors_map_without_fabrication() {
        let invocation = sealed_invocation(TEST_INPUT, TEST_SEED);
        let completed = EngineReport {
            request_digest: invocation.request_digest.clone(),
            termination: EngineTermination::Completed,
            usage: EngineUsage {
                attempted_output_bytes: 3,
                output_bytes: 3,
                host_calls: 0,
                fuel_consumed: 5,
                peak_memory_bytes: None,
                table_elements: None,
                instances: 1,
                stack_bytes: None,
                enforced_stack_limit_bytes: None,
                elapsed_ms: 2,
                effective_epoch_policy: invocation.limits.epoch,
                epoch_ticks: None,
                artifact_reads: 0,
                artifact_bytes: 0,
                accessed_artifact_digests: Vec::new(),
            },
            output: vec![1, 2, 3],
            host_calls: Vec::new(),
            proposed_effects: Vec::new(),
            observed_state_delta: vec![9],
            post_commit_known: true,
        };
        // Unobserved peak memory stays unknown through the mapping.
        assert_eq!(core_outcome_from_report(&completed).peak_memory_bytes, None);
        let terminated = [
            (
                EngineTermination::Trap(crate::TrapClass::GuestTrap),
                ErrorClass::Rejected,
            ),
            (EngineTermination::FuelExhausted, ErrorClass::Rejected),
            (EngineTermination::Cancelled, ErrorClass::Unknown),
            (EngineTermination::Deadline, ErrorClass::Unknown),
            (EngineTermination::PostCommitUnknown, ErrorClass::Unknown),
        ];
        for (termination, expected) in terminated {
            let mut report = completed.clone();
            report.termination = termination;
            assert_eq!(core_outcome_from_report(&report).error_class, expected);
        }

        // Boundary failures become typed outcomes with no observations, and
        // none of them can satisfy activation acceptance.
        let mut denying = DenyingEngine {
            error: PortError::Denied,
        };
        let denied = WasmCoreAdapter::invoke(&mut denying, &invocation);
        assert_eq!(denied.error_class, ErrorClass::Rejected);
        assert_eq!(denied.fuel_consumed, None);
        let mut unavailable = DenyingEngine {
            error: PortError::Unavailable,
        };
        let down = NativeCoreAdapter::invoke(&mut unavailable, &invocation);
        assert_eq!(down.error_class, ErrorClass::Unavailable);
        let reference = DeterministicEchoCore::new(TEST_COMPONENT).invoke(TEST_INPUT, TEST_SEED);
        assert_eq!(
            build_activation_record(
                TEST_COMPONENT,
                3,
                TEST_SEED,
                TEST_INPUT,
                &denied,
                &reference,
                &denied,
            ),
            Err(LifecycleError::ConformanceNotSatisfied)
        );
    }

    #[test]
    fn lifecycle_projection_branches_follow_canonical_machines() {
        // Quiescing is drain in progress: no further evidence required.
        let quiescing = project_lifecycle(&projection_inputs(
            ModuleGenerationState::Quiescing,
            false,
            false,
        ));
        assert_eq!(quiescing, WasmLifecycleState::Draining);
        // A degraded generation drains only while its canary is open.
        let degraded_canary = project_lifecycle(&LifecycleProjectionInputs {
            generation: ModuleGenerationState::Degraded,
            canary_open: true,
            ..projection_inputs(ModuleGenerationState::Degraded, false, false)
        });
        assert_eq!(degraded_canary, WasmLifecycleState::Draining);
        let degraded_bare = project_lifecycle(&projection_inputs(
            ModuleGenerationState::Degraded,
            false,
            false,
        ));
        assert_eq!(degraded_bare, WasmLifecycleState::Built);
        // Terminal evidence wins in priority order.
        let failed = project_lifecycle(&projection_inputs(
            ModuleGenerationState::Failed,
            true,
            true,
        ));
        assert_eq!(failed, WasmLifecycleState::Rejected);
        let drained = project_lifecycle(&projection_inputs(
            ModuleGenerationState::Drained,
            true,
            true,
        ));
        assert_eq!(drained, WasmLifecycleState::Retired);
        let rolled_back = project_lifecycle(&LifecycleProjectionInputs {
            generation: ModuleGenerationState::Active,
            rollback_cutover_committed: true,
            ..projection_inputs(ModuleGenerationState::Active, true, true)
        });
        assert_eq!(rolled_back, WasmLifecycleState::RolledBack);
        // Progress labels follow observed evidence.
        let shadow = project_lifecycle(&LifecycleProjectionInputs {
            generation: ModuleGenerationState::Ready,
            shadow_open: true,
            ..projection_inputs(ModuleGenerationState::Ready, true, true)
        });
        assert_eq!(shadow, WasmLifecycleState::Shadow);
        let draft = project_lifecycle(&projection_inputs(
            ModuleGenerationState::Discovered,
            false,
            false,
        ));
        assert_eq!(draft, WasmLifecycleState::Draft);
        let built = project_lifecycle(&projection_inputs(
            ModuleGenerationState::Ready,
            false,
            false,
        ));
        assert_eq!(built, WasmLifecycleState::Built);
    }

    #[test]
    fn state_migration_contract_is_identity_bound_and_protected() {
        let plan_digest = must(canonical_digest(&(1_u32, 2_u32, "handler-1956")));
        let plan = StateMigrationPlan {
            from_version: 1,
            to_version: 2,
            handler_id: "handler-1956".to_owned(),
            plan_digest,
            reversible: true,
            backup_digest: None,
        };
        let snapshot = StateSnapshot {
            version: 1,
            bytes: b"state".to_vec(),
        };
        // The handler performs the export/import; the contract accepts the
        // candidate only when the identity-bound envelope holds.
        let candidate = StateSnapshot {
            version: 2,
            bytes: b"state-v2".to_vec(),
        };
        let migrated = match migrate_state(&plan, &snapshot, &candidate) {
            Ok(next) => next,
            Err(error) => panic!("migration failed: {error:?}"),
        };
        assert_eq!(migrated, candidate);

        let stateless = StateSnapshot {
            version: 1,
            bytes: Vec::new(),
        };
        let stateless_digest = must(canonical_digest(&(1_u32, 1_u32, "handler-1956")));
        let stateless_plan = StateMigrationPlan {
            from_version: 1,
            to_version: 1,
            handler_id: "handler-1956".to_owned(),
            plan_digest: stateless_digest,
            reversible: true,
            backup_digest: None,
        };
        assert_eq!(
            migrate_state(&stateless_plan, &stateless, &stateless),
            Ok(stateless.clone())
        );

        let wrong_version = StateSnapshot {
            version: 9,
            bytes: b"state".to_vec(),
        };
        assert_eq!(
            migrate_state(&plan, &wrong_version, &candidate),
            Err(LifecycleError::MigrationVersionMismatch)
        );
        let wrong_candidate = StateSnapshot {
            version: 9,
            bytes: b"state".to_vec(),
        };
        assert_eq!(
            migrate_state(&plan, &snapshot, &wrong_candidate),
            Err(LifecycleError::MigrationVersionMismatch)
        );
        // A plan digest that does not bind the declared versions and
        // handler is rejected before any byte is accepted.
        let forged = StateMigrationPlan {
            plan_digest: digest('f'),
            ..plan.clone()
        };
        assert_eq!(
            migrate_state(&forged, &snapshot, &candidate),
            Err(LifecycleError::InvalidField {
                field: "migration.plan_digest"
            })
        );
        let anonymous = StateMigrationPlan {
            handler_id: String::new(),
            ..plan.clone()
        };
        assert_eq!(
            migrate_state(&anonymous, &snapshot, &candidate),
            Err(LifecycleError::InvalidField {
                field: "migration.handler_id"
            })
        );
        let unprotected = StateMigrationPlan {
            reversible: false,
            backup_digest: None,
            ..plan.clone()
        };
        assert_eq!(
            migrate_state(&unprotected, &snapshot, &candidate),
            Err(LifecycleError::MigrationNotReversible)
        );
        let backup_protected = StateMigrationPlan {
            reversible: false,
            backup_digest: Some(digest('b')),
            ..plan.clone()
        };
        assert_eq!(
            migrate_state(&backup_protected, &snapshot, &candidate),
            Ok(candidate.clone())
        );
    }

    #[test]
    fn rollback_seal_covers_dispositions_and_strategy() {
        let base = RollbackRouteRequest {
            cutover_id: "cutover-seal".to_owned(),
            route_scope: "component-seal".to_owned(),
            from_generation: 3,
            to_generation: 2,
            old_epoch: 5,
            new_epoch: 6,
            in_flight: vec![("op-1".to_owned(), InFlightDisposition::DrainRead)],
            snapshot_strategy: SnapshotStrategy::PriorCompatibleSnapshot,
            state_compatible: true,
        };
        let sealed = must_route(route_rollback(&base));
        let other_disposition = RollbackRouteRequest {
            in_flight: vec![(
                "op-1".to_owned(),
                InFlightDisposition::BlockScopeUnknownOutcome,
            )],
            ..base.clone()
        };
        let resealed = must_route(route_rollback(&other_disposition));
        assert_ne!(sealed.route_digest, resealed.route_digest);
        let other_strategy = RollbackRouteRequest {
            snapshot_strategy: SnapshotStrategy::ForwardRepair,
            ..base.clone()
        };
        let restrategized = must_route(route_rollback(&other_strategy));
        assert_ne!(sealed.route_digest, restrategized.route_digest);
        // One operation identity admits exactly one disposition: a
        // conflicting repeat is rejected, an identical repeat is idempotent.
        let conflicting = RollbackRouteRequest {
            in_flight: vec![
                ("op-1".to_owned(), InFlightDisposition::DrainRead),
                ("op-1".to_owned(), InFlightDisposition::CancelProvenNoEffect),
            ],
            ..base.clone()
        };
        assert_eq!(
            route_rollback(&conflicting),
            Err(LifecycleError::RollbackInFlightConflict)
        );
        let idempotent = RollbackRouteRequest {
            in_flight: vec![
                ("op-1".to_owned(), InFlightDisposition::DrainRead),
                ("op-1".to_owned(), InFlightDisposition::DrainRead),
            ],
            ..base.clone()
        };
        assert!(route_rollback(&idempotent).is_ok());
    }
}
