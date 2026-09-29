//! Exact neutral generation preparation, drain, switch, and reconciliation.
//!
//! This module is Slice B of issue #760 (cases 13-39). It owns the local,
//! provider-neutral replacement state machine for `eliot-wasm-runtime`: one
//! exclusive replacement operation at a time, atomic drain linearization, one
//! compare-and-swap admission switch, a second compare-and-swap for an
//! owner-committed rollback cutover, reconciliation of unknown outcomes, and
//! pure rehydration from owner-supplied lifecycle evidence.
//!
//! Rollback boundary (I14.14 "Rollback is another cutover with a newer epoch; an
//! old epoch is never reactivated"; I14.19 "Old epochs are never reactivated"):
//! this coordinator mints no cutover authority. It executes the local
//! admission-target restore only when the caller supplies the owner-committed
//! [`GenerationCutoverReceipt`] that already names the retired and restored
//! generations and carries a strictly newer authority epoch in the active
//! fence's own lineage. Without that evidence the typed answer stays
//! [`ReplacementError::KernelCutoverRequired`]; with it, the restore is still
//! the ordinary drain plus compare-and-swap, so an old epoch is never
//! reactivated — the restored record re-admits under the newer epoch.
//!
//! Authority boundaries (enforced, not merely documented):
//!
//! - The coordinator records externally admitted generations. It never mints
//!   Kernel generation authority, never claims an in-memory pointer update was
//!   durably committed, and never executes guest code. Durable publication and
//!   execution stay with the existing Kernel/ORS, P-03, and engine owners.
//! - Candidate readiness is observed through the caller-supplied
//!   [`ReadinessOracle`]. The production adapter is
//!   [`crate::runtime::EngineReadinessOracle`], reached through
//!   [`crate::runtime::WasmRuntime::prepare_replacement_with_engine`]: it runs
//!   exactly one bounded probe over the already-injected
//!   [`crate::ComponentEnginePort`] and reuses the same engine-report
//!   classification the invocation path uses. Tests supply deterministic
//!   scripted oracles. The coordinator itself performs no I/O and never calls
//!   the oracle while holding its lock.
//! - Rehydration ([`GenerationCoordinator::rehydrate_replacement`]) is a pure
//!   function over an owner-supplied log. It performs no engine observation;
//!   callers that need fresh observations supply them as log entries derived
//!   through the injected stable-generation port.
//!
//! Slice-A seam: world, ABI, and kit identity on a [`GenerationRecord`] are
//! stored as verified digests plus the world string. The canonical producers
//! of those values are the Slice-A typed contract surface (six-world map) and
//! `ModuleContractKit` living under the `crate::component_contract` and
//! `crate::capsule` modules; this module defines no second schema and no
//! competing WIT projection. Call sites construct [`GenerationParams`] from
//! those Slice-A types together with the Governor-admitted manifest, and the
//! coordinator only compares the resulting digests for exact equality.
//!
//! Case map (issue #760, denominator 13-39): preparation failure keeps the old
//! generation (13); drain linearization and old-call completion (14, 15);
//! drain deadline without dual-active (16); atomic expected-old switch with
//! local-only linearization evidence plus later external publication (17);
//! exclusive operation admits exactly one switch (18); stale expectations
//! change nothing (19); post-switch calls acquire the new generation only
//! (20); retention until references clear (21); owner-committed newer-epoch
//! rollback before any new-call admission (22); reconcile-first for possible
//! new calls or unknown receipts (23);
//! rollback drains the new generation then atomically restores the old under
//! the same owner-committed cutover (24-25);
//! incompatibility families (26) including
//! same-version ABI drift (27); per-stage typed failures (28); rehydration
//! with fabricated-durability rejection (29); late old output isolation (30);
//! lost-lease disposal block (31); cancellation before/after acquisition and
//! in drain (32); sequenced receipt replay (33); barrier-driven multithreaded
//! use (34); single acceptance (35), single terminal/unknown disposition (36),
//! no disposal of referenced generations (37), single linearizable switch per
//! replacement (38), and bounded retention under repeated faults (39).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Mutex, MutexGuard};

use eliot_runtime_contracts::{GenerationCutoverReceipt, GenerationCutoverState, ModuleGeneration};
use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;

use crate::{CapabilityId, EngineBinding, InvocationLimits, Sha256Digest, canonical_digest};

/// Maximum concurrently tracked accepted calls (in-flight leases).
pub const MAX_INFLIGHT_CALLS: usize = 512;
/// Maximum retained (non-active, non-quarantined) generation records.
pub const MAX_RETAINED_GENERATIONS: usize = 16;
/// Maximum terminal/unknown call history entries retained as evidence.
pub const MAX_CALL_HISTORY: usize = 1024;
/// Maximum sequenced receipts retained per receipt log (switch/rollback/reconcile).
pub const MAX_RECEIPTS: usize = 64;
/// Maximum generations held in explicit bounded quarantine.
pub const MAX_QUARANTINED_GENERATIONS: usize = 8;
/// Largest admissible candidate artifact in bytes.
pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
/// Largest admissible bounded readiness-probe deadline.
pub const MAX_PROBE_DEADLINE_MS: u64 = 5_000;
/// Largest admissible bounded readiness-probe output.
pub const MAX_PROBE_OUTPUT_BYTES: u64 = 65_536;
/// Largest admissible drain deadline.
pub const MAX_DRAIN_DEADLINE_MS: u64 = 30_000;

/// Typed fail-closed replacement failures. Details carry only non-secret
/// identities (operation/call identifiers, generation numbers, digests, fixed
/// machine-readable codes). Raw payload bytes never appear here.
#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code", content = "detail")]
pub enum ReplacementError {
    /// A text or numeric field violated its structural contract.
    #[error("invalid replacement field: {0}")]
    InvalidField(String),
    /// A generation record violated its structural contract.
    #[error("invalid generation record: {0}")]
    InvalidGeneration(String),
    /// An externally owned contract (module generation, engine binding,
    /// limits) failed validation.
    #[error("external contract rejected: {0}")]
    ExternalContract(String),
    /// The caller-named expected generation (or fence) no longer matches.
    #[error("stale expected generation")]
    StaleExpectedGeneration,
    /// Another exclusive replacement operation already holds the coordinator.
    #[error("replacement operation already in progress")]
    ReplacementInProgress,
    /// No operation with that identity holds the coordinator.
    #[error("unknown replacement operation")]
    UnknownOperation,
    /// No active generation is admitted.
    #[error("no active generation admitted")]
    NoActiveGeneration,
    /// An active generation is already admitted.
    #[error("active generation already admitted")]
    AlreadyActive,
    /// No retained generation carries that number.
    #[error("unknown generation")]
    UnknownGeneration,
    /// No prepared candidate is waiting for drain/switch.
    #[error("no prepared candidate")]
    NoPreparedCandidate,
    /// Drain was not started for the current operation.
    #[error("drain not armed")]
    DrainNotArmed,
    /// Drain is already running for the current operation.
    #[error("drain already active")]
    DrainAlreadyActive,
    /// No lease may be acquired on the old generation after the drain point.
    #[error("admission blocked while draining")]
    AdmissionBlockedDraining,
    /// Unresolved in-flight calls forbid the atomic switch.
    #[error("drain unresolved")]
    DrainUnresolved,
    /// No tracked call carries that identity.
    #[error("unknown call")]
    UnknownCall,
    /// The call already reached a terminal disposition.
    #[error("call already terminal")]
    AlreadyTerminal,
    /// The call identity is already tracked.
    #[error("duplicate call identity")]
    DuplicateCallId,
    /// The bounded in-flight call table is full.
    #[error("in-flight call capacity exceeded")]
    CallCapacityExceeded,
    /// A late outcome tagged with a foreign generation cannot mutate the call.
    #[error("call outcome generation mismatch")]
    GenerationTagMismatch,
    /// A call ID already has a different retained terminal disposition.
    #[error("call terminal disposition conflicts with retained history")]
    TerminalDispositionConflict,
    /// The candidate violates artifact/type/import/limit compatibility.
    #[error("incompatible candidate: {0}")]
    IncompatibleCandidate(String),
    /// The bounded readiness probe reported failure; the old stays active.
    #[error("candidate readiness probe failed")]
    ReadinessFailed,
    /// The readiness oracle reported an unknown outcome.
    #[error("candidate readiness unknown")]
    ReadinessUnknown,
    /// The generation is still referenced by the active, candidate, or pending slot.
    #[error("generation still referenced")]
    ReferencedGeneration,
    /// Open call leases still reference the generation; a lost (never
    /// completed, never cancelled) lease blocks retirement.
    #[error("generation leases unresolved")]
    LeaseUnresolved,
    /// New calls may exist or the switch receipt is unknown: reconcile first.
    #[error("reconciliation required before rollback")]
    ReconciliationRequired,
    /// The caller supplied no owner-committed cutover evidence, so no rollback
    /// is armed. Rollback is a Kernel/ORS cutover with a newer authority epoch;
    /// this coordinator mints neither.
    #[error("rollback requires a Kernel/ORS cutover with a newer authority epoch")]
    KernelCutoverRequired,
    /// The supplied cutover epoch is inside the active fence's own lineage but
    /// is not strictly newer than it. An old epoch is never reactivated.
    #[error("rollback would reactivate an old authority epoch")]
    OldEpochReactivation,
    /// The supplied cutover epoch is outside the active fence's own lineage
    /// (or otherwise not strictly newer), so it cannot order against the active
    /// authority. Equal sequences from different lineages are unrelated.
    #[error("rollback authority epoch is not newer than the active fence")]
    RollbackEpochNotNewer,
    /// The pending candidate is an owner-committed rollback target, not a
    /// forward candidate; its local switch must be completed through
    /// [`GenerationCoordinator::complete_rollback`].
    #[error("rollback cutover pending: complete the rollback instead")]
    RollbackCutoverPending,
    /// The pending candidate is a forward candidate admitted by a bounded
    /// readiness probe, not an owner-committed rollback target, so there is no
    /// armed rollback to complete.
    #[error("no armed rollback for this operation")]
    NoArmedRollback,
    /// Rollback replay carried a different payload than the retained record.
    #[error("rollback payload changed")]
    RollbackPayloadChanged,
    /// The observed active generation disagrees with the switch receipt.
    #[error("observed active generation mismatch")]
    ObservedActiveMismatch,
    /// No receipt carries that sequence.
    #[error("unknown receipt")]
    UnknownReceipt,
    /// The same receipt sequence was presented with different evidence.
    #[error("receipt conflict")]
    ReceiptConflict,
    /// Durable publication was claimed without a preceding local switch.
    #[error("fabricated durability")]
    FabricatedDurability,
    /// The same log sequence carried conflicting entries.
    #[error("log sequence conflict")]
    LogSequenceConflict,
    /// A lifecycle entry does not link to the previously active generation.
    #[error("predecessor mismatch")]
    PredecessorMismatch,
    /// Bounded retention is full and nothing unreferenced may be evicted.
    #[error("bounded retention full")]
    RetentionFull,
    /// Bounded quarantine is full.
    #[error("bounded quarantine full")]
    QuarantineFull,
    /// A coordinator invariant scan failed.
    #[error("replacement invariant violated: {0}")]
    InvariantViolation(String),
    /// The coordinator lock is unavailable.
    #[error("replacement coordinator unavailable")]
    CoordinatorUnavailable,
}

/// State-migration declaration for a candidate generation. Only stateless
/// operation or an explicit reversible plan may enter preparation; an
/// irreversible migration cannot be expressed here and therefore cannot pass
/// validation by construction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", content = "detail")]
pub enum StateMigration {
    /// The generation carries no migratable state.
    Stateless,
    /// State moves under an explicit reversible plan digest.
    Reversible {
        /// Digest of the externally owned reversible migration plan.
        plan_digest: Sha256Digest,
    },
}

/// Constructor parameters for a [`GenerationRecord`]. World, ABI, and kit
/// values are projections of the Slice-A typed contract surface and
/// `ModuleContractKit` (see the module-level seam note); the coordinator
/// compares only the resulting digests and strings for exact equality.
#[derive(Clone, Debug)]
pub struct GenerationParams {
    /// Externally admitted module generation (validated on ingest).
    pub generation: ModuleGeneration,
    /// Lineage predecessor generation number, when one exists.
    pub predecessor: Option<u64>,
    /// Candidate artifact length in bytes.
    pub artifact_len: u64,
    /// Candidate artifact digest; must equal the generation artifact id.
    pub artifact_digest: Sha256Digest,
    /// Slice-A world projection (for example `eliot:test/world` in fixtures).
    pub world: String,
    /// Slice-A component version label (used to classify ABI drift).
    pub component_version: String,
    /// Slice-A ABI map digest; equality is required across a replacement.
    pub abi_digest: Sha256Digest,
    /// Slice-A `ModuleContractKit` digest; equality is required across a replacement.
    pub kit_digest: Sha256Digest,
    /// Host/engine identity bound to this generation.
    pub engine: EngineBinding,
    /// Actually observed imports (never a bare descriptor claim).
    pub observed_imports: BTreeSet<CapabilityId>,
    /// Stateless or explicitly reversible migration declaration.
    pub state_migration: StateMigration,
    /// Operation/scope identity this generation serves.
    pub scope: String,
    /// Per-generation limit envelope; replacements may only narrow it.
    pub limits: InvocationLimits,
}

/// An externally admitted generation bound to its artifact, world/ABI/kit
/// contract, observed imports, engine, migration, scope, and limits. Same
/// bytes do not imply the same generation: identity is the admitted
/// (module, generation number) pair plus the bound artifact digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GenerationRecord {
    generation: ModuleGeneration,
    predecessor: Option<u64>,
    artifact_len: u64,
    artifact_digest: Sha256Digest,
    world: String,
    component_version: String,
    abi_digest: Sha256Digest,
    kit_digest: Sha256Digest,
    engine: EngineBinding,
    observed_imports: BTreeSet<CapabilityId>,
    state_migration: StateMigration,
    scope: String,
    limits: InvocationLimits,
}

impl GenerationRecord {
    /// Validates and binds an externally admitted generation.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when any structural, artifact-binding,
    /// engine-binding, or limit-envelope check fails.
    pub fn new(params: GenerationParams) -> Result<Self, ReplacementError> {
        params
            .generation
            .validate()
            .map_err(|_| external_contract("module-generation-rejected"))?;
        if params.generation.artifact_id.as_str() != params.artifact_digest.as_str() {
            return Err(ReplacementError::InvalidGeneration(
                "artifact-binding-mismatch".to_owned(),
            ));
        }
        if params.artifact_len == 0 {
            return Err(ReplacementError::InvalidGeneration(
                "artifact-empty".to_owned(),
            ));
        }
        if params.artifact_len > MAX_ARTIFACT_BYTES {
            return Err(ReplacementError::InvalidGeneration(
                "artifact-too-large".to_owned(),
            ));
        }
        let number = params.generation.generation.value();
        if params
            .predecessor
            .is_some_and(|predecessor| predecessor >= number)
        {
            return Err(ReplacementError::InvalidGeneration(
                "predecessor-not-older".to_owned(),
            ));
        }
        check_text(&params.world, "record.world")?;
        check_text(&params.component_version, "record.component_version")?;
        check_text(&params.scope, "record.scope")?;
        params
            .engine
            .validate()
            .map_err(|_| invalid_generation("engine-binding-rejected"))?;
        params
            .limits
            .validate(&params.artifact_digest)
            .map_err(|_| invalid_generation("limit-envelope-rejected"))?;
        Ok(Self {
            generation: params.generation,
            predecessor: params.predecessor,
            artifact_len: params.artifact_len,
            artifact_digest: params.artifact_digest,
            world: params.world,
            component_version: params.component_version,
            abi_digest: params.abi_digest,
            kit_digest: params.kit_digest,
            engine: params.engine,
            observed_imports: params.observed_imports,
            state_migration: params.state_migration,
            scope: params.scope,
            limits: params.limits,
        })
    }

    /// Returns the admitted generation number.
    #[must_use]
    pub const fn generation_number(&self) -> u64 {
        self.generation.generation.value()
    }

    /// Returns the bound artifact digest.
    #[must_use]
    pub const fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }

    /// Returns the admitted module identity.
    #[must_use]
    pub fn module_id(&self) -> &str {
        self.generation.module_id.as_str()
    }

    /// Returns the Slice-A world projection.
    #[must_use]
    pub fn world(&self) -> &str {
        &self.world
    }
}

/// Off-path candidate offered for preparation: the bound record plus the
/// declared bounded readiness-probe envelope. Only this probe may run before
/// the switch; its exact result is retained on the prepared candidate.
#[derive(Clone, Debug)]
pub struct CandidateDescriptor {
    /// The candidate generation record.
    pub record: GenerationRecord,
    /// Digest of the declared probe input.
    pub probe_input_digest: Sha256Digest,
    /// Declared probe deadline in milliseconds.
    pub probe_deadline_ms: u64,
    /// Declared probe output ceiling in bytes.
    pub max_probe_output_bytes: u64,
}

impl CandidateDescriptor {
    fn validate_for_prepare(&self) -> Result<(), ReplacementError> {
        if self.probe_deadline_ms == 0 || self.probe_deadline_ms > MAX_PROBE_DEADLINE_MS {
            return Err(ReplacementError::InvalidField(
                "candidate.probe_deadline_ms".to_owned(),
            ));
        }
        if self.max_probe_output_bytes == 0 || self.max_probe_output_bytes > MAX_PROBE_OUTPUT_BYTES
        {
            return Err(ReplacementError::InvalidField(
                "candidate.max_probe_output_bytes".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Exclusive preparation request: the caller-chosen operation identity, the
/// exact expected current generation, and the off-path candidate.
#[derive(Clone, Debug)]
pub struct PrepareRequest {
    /// Caller-chosen exclusive operation identity.
    pub operation_id: String,
    /// Exact expected currently active generation number.
    pub expected_active: u64,
    /// Candidate prepared off-path.
    pub candidate: CandidateDescriptor,
}

/// Exact retained readiness result for a prepared candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadinessEvidence {
    /// Candidate generation number the probe observed.
    pub generation: u64,
    /// Digest of the exact probe output.
    pub probe_output_digest: Sha256Digest,
    /// Whether the declared bounded probe passed.
    pub success: bool,
}

/// Fixed readiness oracle. Production adapters run only the declared bounded
/// probe through the injected engine; deterministic tests script exact
/// outcomes. The coordinator never calls this oracle while holding its lock.
pub trait ReadinessOracle {
    /// Runs the declared bounded probe for the candidate.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::ReadinessUnknown`] (or another typed
    /// failure) when the probe outcome is unknown or the oracle faults.
    fn probe(
        &mut self,
        candidate: &CandidateDescriptor,
    ) -> Result<ReadinessEvidence, ReplacementError>;
}

/// Summary returned when preparation stores a ready candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreparedSummary {
    /// Exclusive operation identity holding the coordinator.
    pub operation_id: String,
    /// Prepared candidate generation number.
    pub candidate_generation: u64,
    /// Digest of the retained readiness output.
    pub readiness_digest: Sha256Digest,
}

/// Atomic switch request: the holding operation, the rechecked expected
/// generation, and nothing else. The fence recheck compares the active fence
/// against the fence observed at preparation time inside the coordinator.
#[derive(Clone, Debug)]
pub struct SwitchRequest {
    /// Exclusive operation identity holding the prepared candidate.
    pub operation_id: String,
    /// Rechecked expected currently active generation number.
    pub expected_active: u64,
}

/// Local switch receipt. The compare-and-swap of the admission target is the
/// local new-call linearization point only; `durable_published` stays false
/// until the durable owner (Kernel/ORS) observation is attached with
/// [`GenerationCoordinator::note_external_publication`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SwitchReceipt {
    /// Coordinator receipt sequence.
    pub sequence: u64,
    /// Operation that performed the switch.
    pub operation_id: String,
    /// Retired generation number.
    pub old_generation: u64,
    /// Newly admitted generation number.
    pub new_generation: u64,
    /// Retired artifact digest.
    pub old_artifact: Sha256Digest,
    /// Newly admitted artifact digest.
    pub new_artifact: Sha256Digest,
    /// Exact in-flight count at the switch (always zero).
    pub inflight_at_switch: u64,
    /// Digest over the exact (empty) unresolved call list at the switch.
    pub inflight_digest: Sha256Digest,
    /// Previous receipt-chain digest (genesis digest for the first receipt).
    pub prev_receipt_digest: Sha256Digest,
    /// Sealing digest over this receipt and its chain link.
    pub receipt_digest: Sha256Digest,
    /// True once durable-owner publication evidence is attached.
    pub durable_published: bool,
    /// Durable-owner evidence digest, when attached.
    pub external_evidence: Option<Sha256Digest>,
}

/// Snapshot captured atomically when drain begins: the draining generation and
/// the exact unresolved call identities observed at the drain point.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrainSnapshot {
    /// Operation holding the drain.
    pub operation_id: String,
    /// Generation being drained (the still-active old generation).
    pub draining_generation: u64,
    /// Exact unresolved call identities at the drain point.
    pub unresolved: Vec<String>,
    /// Admitted drain deadline in milliseconds.
    pub deadline_ms: u64,
}

/// Observable drain state. `blocked` records that a deadline passed with
/// unresolved calls; it never implies two active targets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrainStatus {
    /// Whether a drain is armed.
    pub draining: bool,
    /// Generation being drained, when armed.
    pub draining_generation: Option<u64>,
    /// Currently unresolved call identities on the draining generation.
    pub unresolved: Vec<String>,
    /// Whether a deadline passed while calls were unresolved.
    pub blocked: bool,
    /// Admitted drain deadline in milliseconds, when armed.
    pub deadline_ms: Option<u64>,
}

/// Per-call disposition. Every accepted call ends with exactly one of the
/// terminal dispositions (`Completed`, `Cancelled`) or `Unknown`; `Accepted`
/// exists only while the call is tracked in flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallDisposition {
    /// Lease acquired; invocation may proceed on the accepting generation.
    Accepted,
    /// Observed terminal success on the accepting generation.
    Completed,
    /// Cancelled with proven no-effect.
    Cancelled,
    /// Outcome unknown; reconciliation owns the call.
    Unknown,
}

/// Generation lease acquired atomically for one new call before invocation.
/// The lease is retained until the call's own observed terminal or unknown
/// result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallLease {
    /// Tracked call identity.
    pub call_id: String,
    /// The single generation that accepted this call.
    pub accepted_generation: u64,
    /// Current disposition.
    pub disposition: CallDisposition,
}

/// Terminal outcome observed for one call, tagged with the generation that
/// produced it. A tag that disagrees with the accepting lease is rejected
/// without mutating any call.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallTerminal {
    /// Terminal success.
    Completed,
    /// Terminal cancellation.
    Cancelled,
    /// Post-commit unknown outcome.
    Unknown,
}

/// Outcome presented for call completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallOutcome {
    /// Tracked call identity.
    pub call_id: String,
    /// Generation tag carried by the observed outcome.
    pub generation: u64,
    /// Observed terminal value.
    pub terminal: CallTerminal,
}

/// Result of presenting a call outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallCompletion {
    /// The terminal/unknown disposition was recorded.
    RecordedTerminal,
    /// Duplicate delivery of an already-recorded terminal outcome; replayed
    /// without mutation.
    DuplicateReplay,
}

/// Rollback identity, retained target evidence, and the owner-committed
/// cutover that authorises the restore.
///
/// The coordinator never mints a cutover. `cutover` is the
/// [`GenerationCutoverReceipt`] Kernel/ORS emitted for this exact rollback
/// (I14.14: the ORS commit is the durable linearization point, and the receipt
/// is the operational proof of it); `cutover_digest` is its canonical digest,
/// checked for exact equality so a caller cannot relabel one receipt as another.
/// `None` is not a weaker request: it is the typed refusal
/// [`ReplacementError::KernelCutoverRequired`].
#[derive(Clone, Debug)]
pub struct RollbackRequest {
    /// Caller-chosen exclusive rollback operation identity.
    pub operation_id: String,
    /// Rechecked currently active generation number.
    pub expected_current: u64,
    /// Retained generation number Kernel/ORS committed as the new route.
    pub target_generation: u64,
    /// Expected retained target artifact digest, used only for local validation.
    pub target_artifact: Sha256Digest,
    /// Owner-committed cutover receipt authorising the restore, or `None` to
    /// obtain the typed refusal.
    pub cutover: Option<GenerationCutoverReceipt>,
    /// Canonical digest of `cutover`; must equal it exactly.
    pub cutover_digest: Option<Sha256Digest>,
}

/// Summary returned when rollback arming succeeds. Arming holds the exclusive
/// operation and pins the retained target, so the ordinary
/// [`GenerationCoordinator::begin_drain`] can drain the generation being
/// retired; it does not itself change the admission target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RollbackArmed {
    /// Exclusive rollback operation identity.
    pub operation_id: String,
    /// Generation being drained and retired.
    pub current_generation: u64,
    /// Retained generation the owner-committed cutover restores.
    pub target_generation: u64,
    /// Canonical digest of the owner-committed
    /// [`GenerationCutoverReceipt`] that authorised this arm, pinned to the
    /// pending candidate. It is the exact owner authority under which the drain
    /// runs, so the caller can prove *which* cutover is in flight rather than
    /// only that some rollback is.
    pub cutover_digest: Sha256Digest,
}

/// Local rollback receipt. It records the same local compare-and-swap of the
/// admission target that a switch does; the durable cutover it executes is
/// owned by Kernel/ORS and proved by the [`GenerationCutoverReceipt`] the
/// request supplied, not by this receipt. `restored_generation` is a re-admitted
/// generation under a newer epoch, never a reactivated old epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RollbackReceipt {
    /// Coordinator receipt sequence.
    pub sequence: u64,
    /// Rollback operation identity.
    pub operation_id: String,
    /// Generation retired by the rollback.
    pub from_generation: u64,
    /// Generation the owner-committed cutover restored.
    pub restored_generation: u64,
    /// Artifact digest bound to the restored generation.
    pub restored_artifact: Sha256Digest,
    /// Canonical digest of the exact owner-committed cutover consumed by this
    /// rollback. This field intentionally changes the receipt schema: legacy
    /// receipts without cutover identity cannot attest which authority epoch
    /// became the effective activation fence.
    pub cutover_digest: Sha256Digest,
    /// Accepted calls on the retired generation retained as history.
    pub new_calls_retained: u64,
    /// Previous receipt-chain digest.
    pub prev_receipt_digest: Sha256Digest,
    /// Sealing digest over this receipt and its chain link.
    pub receipt_digest: Sha256Digest,
}

/// Observed generation supplied for reconciliation of an unknown switch. The
/// observation itself comes from the caller (derived through the injected
/// stable-generation port); the coordinator only validates and records it.
#[derive(Clone, Debug)]
pub struct ObservedGeneration {
    /// Switch operation under question.
    pub operation_id: String,
    /// Generation observed as active.
    pub observed_active: u64,
    /// Digest of the observation evidence.
    pub evidence: Sha256Digest,
}

/// Reconciliation receipt: the unknown switch is resolved to exactly one
/// observed active generation instead of a blind rollback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconcileReceipt {
    /// Coordinator receipt sequence.
    pub sequence: u64,
    /// Switch operation that was unknown.
    pub operation_id: String,
    /// Generation observed (and now confirmed) as active.
    pub observed_active: u64,
    /// Digest of the observation evidence.
    pub evidence: Sha256Digest,
    /// Previous receipt-chain digest.
    pub prev_receipt_digest: Sha256Digest,
    /// Sealing digest over this receipt and its chain link.
    pub receipt_digest: Sha256Digest,
}

/// Lifecycle event kinds understood by pure rehydration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleEventKind {
    /// Candidate prepared off-path.
    Prepared,
    /// Drain began on the active generation.
    DrainBegan,
    /// Admission target switched to `generation`.
    Switched,
    /// Owner-supplied history says rollback completed to `generation`.
    RollbackCompleted,
    /// A retained generation was retired.
    Retired,
    /// Durable owner published `generation`.
    ExternallyPublished,
}

/// One owner-supplied lifecycle log entry. `previous_active` links the entry
/// to the previously active generation (not the lineage predecessor); it is
/// `None` only when no generation was active before this entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LifecycleLogEntry {
    /// Exact log sequence; duplicates are replay, conflicts are rejected.
    pub sequence: u64,
    /// Generation the entry concerns.
    pub generation: u64,
    /// Previously active generation, when one existed.
    pub previous_active: Option<u64>,
    /// Artifact digest bound to `generation` in this entry.
    pub artifact: Sha256Digest,
    /// Event kind.
    pub kind: LifecycleEventKind,
}

/// Pure rehydration result: exactly one of active, no-active, or unknown.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "state", content = "detail")]
pub enum RehydratedState {
    /// Exactly one generation derives as active.
    Active {
        /// Derived active generation number.
        generation: u64,
        /// Derived active artifact digest.
        artifact: Sha256Digest,
    },
    /// No generation derives as active.
    NoActive,
    /// Evidence is gapped or the active generation was retired beneath the
    /// observer; the state is unknown, never guessed.
    Unknown,
}

/// Why the pending candidate may take the admission target. A forward
/// candidate is admitted by its retained bounded probe result; a rollback
/// target is admitted by the owner-committed cutover, never by a probe — the
/// retained generation already passed readiness when it was first prepared, and
/// fabricating a fresh probe result here would invent evidence.
#[derive(Clone, Debug)]
enum CandidateBasis {
    Probe(ReadinessEvidence),
    CommittedCutover { cutover: GenerationCutoverReceipt },
}

impl CandidateBasis {
    /// The owner-committed cutover a pending rollback target is armed under, or
    /// `None` for a forward candidate.
    fn committed_cutover(&self) -> Option<&GenerationCutoverReceipt> {
        match self {
            Self::Probe(_) => None,
            Self::CommittedCutover { cutover } => Some(cutover),
        }
    }
}

#[derive(Clone, Debug)]
struct PreparedCandidate {
    record: GenerationRecord,
    basis: CandidateBasis,
    operation_id: String,
    active_number: u64,
    active_fence_digest: Sha256Digest,
}

/// Effective activation of a generation. `record` remains the immutable
/// admitted description (including its historical registration fence), while
/// a rollback receipt, when present, supplies the newer current fence.
#[derive(Clone, Debug)]
struct ActiveBinding {
    record: GenerationRecord,
    rollback_cutover: Option<GenerationCutoverReceipt>,
}

impl ActiveBinding {
    fn initial(record: GenerationRecord) -> Self {
        Self {
            record,
            rollback_cutover: None,
        }
    }

    fn generation_number(&self) -> u64 {
        self.record.generation_number()
    }

    fn effective_fence_digest(&self) -> Result<Sha256Digest, ReplacementError> {
        let cutover_digest = self
            .rollback_cutover
            .as_ref()
            .map(canonical_digest)
            .transpose()
            .map_err(|_| external_contract("fence-seal-failed"))?;
        canonical_digest(&ActiveFenceIdentity {
            registration_fence: &self.record.generation.state_fence,
            rollback_cutover_digest: cutover_digest.as_ref(),
        })
        .map_err(|_| external_contract("fence-seal-failed"))
    }
}

#[derive(Serialize)]
struct ActiveFenceIdentity<'a, T> {
    registration_fence: &'a T,
    rollback_cutover_digest: Option<&'a Sha256Digest>,
}

#[derive(Clone, Debug)]
struct DrainState {
    operation_id: String,
    generation: u64,
    deadline_ms: u64,
    blocked: bool,
}

#[derive(Clone, Debug)]
struct AdoptionInfo {
    operation_id: String,
    calls_accepted_since: u64,
    confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CallHistoryEntry {
    call_id: String,
    generation: u64,
    disposition: CallDisposition,
}

#[derive(Clone, Debug)]
struct QuarantinedGeneration {
    record: GenerationRecord,
    evidence: Sha256Digest,
}

struct CoordinatorState {
    active: Option<ActiveBinding>,
    adoption: Option<AdoptionInfo>,
    candidate: Option<PreparedCandidate>,
    operation: Option<String>,
    draining: Option<DrainState>,
    inflight: BTreeMap<String, CallLease>,
    history: VecDeque<CallHistoryEntry>,
    retained: BTreeMap<u64, GenerationRecord>,
    quarantined: BTreeMap<u64, QuarantinedGeneration>,
    switch_log: VecDeque<SwitchReceipt>,
    rollback_log: VecDeque<RollbackReceipt>,
    reconcile_log: VecDeque<ReconcileReceipt>,
    sequence: u64,
    chain_head: Option<Sha256Digest>,
}

impl CoordinatorState {
    const fn new() -> Self {
        Self {
            active: None,
            adoption: None,
            candidate: None,
            operation: None,
            draining: None,
            inflight: BTreeMap::new(),
            history: VecDeque::new(),
            retained: BTreeMap::new(),
            quarantined: BTreeMap::new(),
            switch_log: VecDeque::new(),
            rollback_log: VecDeque::new(),
            reconcile_log: VecDeque::new(),
            sequence: 0,
            chain_head: None,
        }
    }

    fn holds_operation(&self, operation_id: &str) -> bool {
        self.operation.as_deref() == Some(operation_id)
    }

    fn candidate_held_by(&self, operation_id: &str) -> bool {
        self.candidate
            .as_ref()
            .is_some_and(|candidate| candidate.operation_id == operation_id)
    }

    fn unresolved_on(&self, generation: u64) -> Vec<String> {
        self.inflight
            .values()
            .filter(|lease| lease.accepted_generation == generation)
            .map(|lease| lease.call_id.clone())
            .collect()
    }

    fn next_sequence(&mut self) -> Result<u64, ReplacementError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ReplacementError::RetentionFull)?;
        Ok(self.sequence)
    }

    fn chain_prev(&self) -> Sha256Digest {
        self.chain_head.clone().unwrap_or_else(genesis_digest)
    }

    fn push_history(&mut self, entry: CallHistoryEntry) {
        if self.history.len() >= MAX_CALL_HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(entry);
    }

    /// A generation held by the pending candidate slot is retained until the
    /// operation resolves. That slot carries both bases: a forward candidate
    /// and, equally, the retained generation an in-progress rollback has armed
    /// to restore. I14.24 case 21 requires the old generation to survive until
    /// no exact call *or* rollback references it, so a pending rollback pins
    /// its own target against `evictible_retained` for as long as the arm lives.
    fn referenced_elsewhere(&self, generation: u64) -> bool {
        self.candidate
            .as_ref()
            .is_some_and(|candidate| candidate.record.generation_number() == generation)
    }

    /// The only eviction candidate set is `retained`, and a generation is only
    /// evictible when nothing pins it. A generation that `complete_rollback`
    /// restored is removed from `retained` and becomes `active`, so it is
    /// outside this universe entirely and can never be its own eviction victim;
    /// before that commit it is both retained and pinned by
    /// [`Self::referenced_elsewhere`], so it is unreachable here too.
    fn evictible_retained(&self) -> Option<u64> {
        self.retained.keys().find_map(|number| {
            let referenced = self
                .inflight
                .values()
                .any(|lease| lease.accepted_generation == *number)
                || self.referenced_elsewhere(*number);
            if referenced { None } else { Some(*number) }
        })
    }

    fn retain_old(&mut self, record: GenerationRecord) -> Result<(), ReplacementError> {
        while self.retained.len() >= MAX_RETAINED_GENERATIONS {
            let Some(evictible) = self.evictible_retained() else {
                return Err(ReplacementError::RetentionFull);
            };
            self.retained.remove(&evictible);
        }
        self.retained.insert(record.generation_number(), record);
        Ok(())
    }
}

/// Neutral generation-replacement coordinator. Interior mutability (behind a
/// single mutex held only across short critical sections, never across oracle
/// calls) makes barrier-controlled multithreaded acquisition, replacement,
/// and rollback deterministic without sleeps.
pub struct GenerationCoordinator {
    state: Mutex<CoordinatorState>,
}

impl GenerationCoordinator {
    /// Creates an empty coordinator with no admitted generation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(CoordinatorState::new()),
        }
    }

    /// Records the first externally admitted generation. Later generations
    /// arrive through prepare/switch, or through
    /// `arm_rollback`/`complete_rollback`
    /// when Kernel/ORS has committed a newer-epoch cutover restoring a retained
    /// generation.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when a generation is already active or the
    /// record is invalid.
    pub fn admit_initial(&self, record: &GenerationRecord) -> Result<u64, ReplacementError> {
        let mut state = self.lock_state()?;
        if state.active.is_some() {
            return Err(ReplacementError::AlreadyActive);
        }
        let number = record.generation_number();
        state.active = Some(ActiveBinding::initial(record.clone()));
        state.adoption = Some(AdoptionInfo {
            operation_id: "initial-admission".to_owned(),
            calls_accepted_since: 0,
            confirmed: true,
        });
        Ok(number)
    }

    /// Returns the currently admitted (new-call) generation number, if any.
    #[must_use]
    pub fn active_generation_number(&self) -> Option<u64> {
        self.lock_state()
            .ok()
            .and_then(|state| state.active.as_ref().map(ActiveBinding::generation_number))
    }

    /// Validates the exclusive operation, the exact expected generation, and
    /// artifact/type/import/limit compatibility, then runs only the declared
    /// bounded readiness probe through the oracle. Probe failure leaves the
    /// old generation active and holds nothing.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when another operation holds the coordinator,
    /// the expectation is stale, the candidate is incompatible, or the probe
    /// fails or reports unknown.
    pub fn prepare(
        &self,
        request: &PrepareRequest,
        oracle: &mut dyn ReadinessOracle,
    ) -> Result<PreparedSummary, ReplacementError> {
        check_text(&request.operation_id, "replacement.operation_id")?;
        request.candidate.record.validate_owned()?;
        request.candidate.validate_for_prepare()?;
        let active_snapshot = self.claim_operation_for_prepare(request)?;
        let evidence = match oracle.probe(&request.candidate) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.release_operation(&request.operation_id);
                return Err(error);
            }
        };
        self.store_candidate(request, &active_snapshot, &evidence)
    }

    /// Atomically begins drain of the still-active old generation under the
    /// same synchronization rule as new-call admission: after this point no
    /// lease may be acquired on the old generation.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the operation is unknown, drain is not
    /// armed by a prepared candidate, or the deadline is unbounded.
    pub fn begin_drain(
        &self,
        operation_id: &str,
        drain_deadline_ms: u64,
    ) -> Result<DrainSnapshot, ReplacementError> {
        check_text(operation_id, "replacement.operation_id")?;
        if drain_deadline_ms == 0 || drain_deadline_ms > MAX_DRAIN_DEADLINE_MS {
            return Err(ReplacementError::InvalidField(
                "replacement.drain_deadline_ms".to_owned(),
            ));
        }
        let mut state = self.lock_state()?;
        if !state.holds_operation(operation_id) {
            return Err(ReplacementError::UnknownOperation);
        }
        if state.draining.is_some() {
            return Err(ReplacementError::DrainAlreadyActive);
        }
        if !state.candidate_held_by(operation_id) {
            return Err(ReplacementError::DrainNotArmed);
        }
        let Some(active) = state.active.as_ref() else {
            return Err(ReplacementError::NoActiveGeneration);
        };
        let draining_generation = active.generation_number();
        let unresolved = state.unresolved_on(draining_generation);
        state.draining = Some(DrainState {
            operation_id: operation_id.to_owned(),
            generation: draining_generation,
            deadline_ms: drain_deadline_ms,
            blocked: false,
        });
        Ok(DrainSnapshot {
            operation_id: operation_id.to_owned(),
            draining_generation,
            unresolved,
            deadline_ms: drain_deadline_ms,
        })
    }

    /// Observes the current drain state without mutating it.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::CoordinatorUnavailable`] when the lock is
    /// unavailable.
    pub fn drain_status(&self) -> Result<DrainStatus, ReplacementError> {
        let state = self.lock_state()?;
        Ok(match state.draining.as_ref() {
            None => DrainStatus {
                draining: false,
                draining_generation: None,
                unresolved: Vec::new(),
                blocked: false,
                deadline_ms: None,
            },
            Some(drain) => DrainStatus {
                draining: true,
                draining_generation: Some(drain.generation),
                unresolved: state.unresolved_on(drain.generation),
                blocked: drain.blocked,
                deadline_ms: Some(drain.deadline_ms),
            },
        })
    }

    /// Notes that the drain deadline passed. With unresolved calls this leaves
    /// a blocked/unknown drain; it never creates two active targets. The
    /// operation stays alive so late completions may still drain and switch.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the operation or drain is unknown.
    pub fn note_drain_deadline(&self, operation_id: &str) -> Result<DrainStatus, ReplacementError> {
        let mut state = self.lock_state()?;
        if !state.holds_operation(operation_id) {
            return Err(ReplacementError::UnknownOperation);
        }
        let Some(drain) = state.draining.as_ref() else {
            return Err(ReplacementError::DrainNotArmed);
        };
        if drain.operation_id != operation_id {
            return Err(ReplacementError::UnknownOperation);
        }
        let draining_generation = drain.generation;
        let drain_deadline_ms = drain.deadline_ms;
        let mut blocked = drain.blocked;
        let unresolved = state.unresolved_on(draining_generation);
        if !unresolved.is_empty() {
            blocked = true;
        }
        if let Some(drain) = state.draining.as_mut() {
            drain.blocked = blocked;
        }
        Ok(DrainStatus {
            draining: true,
            draining_generation: Some(draining_generation),
            unresolved,
            blocked,
            deadline_ms: Some(drain_deadline_ms),
        })
    }

    /// Atomically acquires and registers one new-call lease on the current
    /// admission target. Each new call has at most one accepting generation.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when no generation is active, drain blocks new
    /// admission, the identity is duplicated, or bounded capacity is full.
    pub fn acquire_call(&self, call_id: &str) -> Result<CallLease, ReplacementError> {
        check_text(call_id, "call.call_id")?;
        let mut state = self.lock_state()?;
        let Some(active) = state.active.as_ref() else {
            return Err(ReplacementError::NoActiveGeneration);
        };
        if state.draining.is_some() {
            return Err(ReplacementError::AdmissionBlockedDraining);
        }
        if state.inflight.contains_key(call_id)
            || state.history.iter().any(|entry| entry.call_id == call_id)
        {
            return Err(ReplacementError::DuplicateCallId);
        }
        if state.inflight.len() >= MAX_INFLIGHT_CALLS {
            return Err(ReplacementError::CallCapacityExceeded);
        }
        let lease = CallLease {
            call_id: call_id.to_owned(),
            accepted_generation: active.generation_number(),
            disposition: CallDisposition::Accepted,
        };
        state.inflight.insert(call_id.to_owned(), lease.clone());
        if let Some(adoption) = state.adoption.as_mut() {
            adoption.calls_accepted_since = adoption.calls_accepted_since.saturating_add(1);
        }
        Ok(lease)
    }

    /// Records the call's own observed terminal or unknown result. The
    /// outcome generation tag must equal the accepting lease; late old output
    /// therefore cannot mutate a new call. A duplicate replays only when its
    /// retained generation and disposition are exactly equal; contradictory
    /// terminal delivery is rejected unchanged.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for unknown calls, generation-tag mismatch, or
    /// contradictory terminal history.
    pub fn complete_call(&self, outcome: &CallOutcome) -> Result<CallCompletion, ReplacementError> {
        check_text(&outcome.call_id, "call.call_id")?;
        let disposition = match outcome.terminal {
            CallTerminal::Completed => CallDisposition::Completed,
            CallTerminal::Cancelled => CallDisposition::Cancelled,
            CallTerminal::Unknown => CallDisposition::Unknown,
        };
        let mut state = self.lock_state()?;
        let Some(lease) = state.inflight.get(&outcome.call_id).cloned() else {
            let Some(entry) = state
                .history
                .iter()
                .find(|entry| entry.call_id == outcome.call_id)
            else {
                return Err(ReplacementError::UnknownCall);
            };
            if entry.generation != outcome.generation {
                return Err(ReplacementError::GenerationTagMismatch);
            }
            return if entry.disposition == disposition {
                Ok(CallCompletion::DuplicateReplay)
            } else {
                Err(ReplacementError::TerminalDispositionConflict)
            };
        };
        if lease.accepted_generation != outcome.generation {
            return Err(ReplacementError::GenerationTagMismatch);
        }
        state.inflight.remove(&outcome.call_id);
        state.push_history(CallHistoryEntry {
            call_id: outcome.call_id.clone(),
            generation: outcome.generation,
            disposition,
        });
        Ok(CallCompletion::RecordedTerminal)
    }

    /// Cancels a tracked call. Proven no-effect cancellation is terminal;
    /// unproven cancellation moves the lease to `Unknown` (still tracked in
    /// flight, still blocking drain) for reconciliation.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for unknown or already-terminal calls.
    pub fn cancel_call(
        &self,
        call_id: &str,
        no_effect_proven: bool,
    ) -> Result<CallLease, ReplacementError> {
        check_text(call_id, "call.call_id")?;
        let mut state = self.lock_state()?;
        let Some(lease) = state.inflight.get(call_id).cloned() else {
            if state.history.iter().any(|entry| entry.call_id == call_id) {
                return Err(ReplacementError::AlreadyTerminal);
            }
            return Err(ReplacementError::UnknownCall);
        };
        if no_effect_proven {
            state.inflight.remove(call_id);
            state.push_history(CallHistoryEntry {
                call_id: lease.call_id.clone(),
                generation: lease.accepted_generation,
                disposition: CallDisposition::Cancelled,
            });
            Ok(CallLease {
                disposition: CallDisposition::Cancelled,
                ..lease
            })
        } else {
            let unknown = CallLease {
                disposition: CallDisposition::Unknown,
                ..lease
            };
            state.inflight.insert(call_id.to_owned(), unknown.clone());
            Ok(unknown)
        }
    }

    /// Performs the single atomic compare-and-swap of the admission target
    /// after exact in-flight closure and candidate-readiness recheck. This is
    /// the local new-call linearization point, not durable publication.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the operation, candidate, drain, or
    /// expectation does not validate, or when in-flight calls are unresolved.
    pub fn switch(&self, request: &SwitchRequest) -> Result<SwitchReceipt, ReplacementError> {
        check_text(&request.operation_id, "replacement.operation_id")?;
        let mut state = self.lock_state()?;
        state.check_switch(request)?;
        state.commit_switch(request)
    }

    /// Attaches durable-owner publication evidence to a local switch receipt.
    /// Identical duplicate delivery replays; conflicting evidence for the same
    /// sequence is rejected.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for unknown sequences or conflicting evidence.
    pub fn note_external_publication(
        &self,
        sequence: u64,
        evidence: Sha256Digest,
    ) -> Result<SwitchReceipt, ReplacementError> {
        let mut state = self.lock_state()?;
        let Some(receipt) = state
            .switch_log
            .iter_mut()
            .find(|receipt| receipt.sequence == sequence)
        else {
            return Err(ReplacementError::UnknownReceipt);
        };
        match receipt.external_evidence.as_ref() {
            Some(existing) if *existing == evidence => Ok(receipt.clone()),
            Some(_) => Err(ReplacementError::ReceiptConflict),
            None => {
                receipt.external_evidence = Some(evidence);
                receipt.durable_published = true;
                let confirmed = receipt.clone();
                let adoption_matches = state
                    .adoption
                    .as_ref()
                    .is_some_and(|adoption| adoption.operation_id == confirmed.operation_id);
                if let Some(adoption) = state.adoption.as_mut().filter(|_| adoption_matches) {
                    adoption.confirmed = true;
                }
                Ok(confirmed)
            }
        }
    }

    /// Arms an exact old/new rollback, gated on owner-committed newer-epoch
    /// evidence.
    ///
    /// Rollback is a second cutover, not a restoration (I14.19): the retained
    /// generation stops nothing by itself, the currently active generation is
    /// drained like any other replacement, and the admission target is moved by
    /// the same single compare-and-swap in [`Self::complete_rollback`]. The
    /// coordinator supplies no authority. The caller must present the
    /// [`GenerationCutoverReceipt`] Kernel/ORS committed for this restore, and
    /// it must (a) validate through its own `validate()`, (b) be `Completed`,
    /// (c) name exactly `expected_current` as the retired generation and
    /// `target_generation` as the restored one, and (d) carry an authority
    /// epoch in the active fence's own lineage with a strictly greater
    /// sequence. An old epoch is never reactivated and a foreign lineage is
    /// never ordered against the active authority.
    ///
    /// On success the exclusive operation is held and the retained target is
    /// pinned, so the existing [`Self::begin_drain`] arms the drain and no new
    /// lease is acquired on the generation being retired.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::KernelCutoverRequired`] when the caller
    /// supplies no cutover evidence, and otherwise a typed failure for an
    /// invalid expectation, a missing or changed retained target, an
    /// incompatible target, unresolved new calls or an unknown switch receipt
    /// ([`ReplacementError::ReconciliationRequired`]), or cutover evidence that
    /// does not validate as a newer-epoch cutover. A refusal arms nothing and
    /// leaves operation, drain, call history, and receipts unchanged.
    pub fn arm_rollback(
        &self,
        request: &RollbackRequest,
    ) -> Result<RollbackArmed, ReplacementError> {
        check_text(&request.operation_id, "replacement.operation_id")?;
        let mut state = self.lock_state()?;
        if state.operation.is_some() {
            return Err(ReplacementError::ReplacementInProgress);
        }
        let Some(active) = state.active.clone() else {
            return Err(ReplacementError::NoActiveGeneration);
        };
        if active.generation_number() != request.expected_current {
            return Err(ReplacementError::StaleExpectedGeneration);
        }
        if request.target_generation == request.expected_current {
            return Err(ReplacementError::InvalidField(
                "rollback.target_generation".to_owned(),
            ));
        }
        let Some(target) = state.retained.get(&request.target_generation).cloned() else {
            return Err(ReplacementError::UnknownGeneration);
        };
        if target.artifact_digest != request.target_artifact {
            return Err(ReplacementError::RollbackPayloadChanged);
        }
        // Direction-agnostic compatibility only. `check_compatible` additionally
        // refuses a generation-number regression, which is correct for a forward
        // replacement and would make the restore direction unreachable.
        check_compatible_fields(&active.record, &target)?;
        if let Some(adoption) = state.adoption.as_ref() {
            let risky = !adoption.confirmed || adoption.calls_accepted_since > 0;
            let reconciled = state
                .reconcile_log
                .iter()
                .any(|receipt| receipt.operation_id == adoption.operation_id);
            if risky && !reconciled {
                return Err(ReplacementError::ReconciliationRequired);
            }
        }
        // The owner evidence is pinned, not just its digest: the completion CAS
        // re-validates this exact receipt under the same lock, so a rollback can
        // only be completed under the cutover that armed it.
        let cutover = check_rollback_cutover(request, &active)?;
        let cutover_digest = request
            .cutover_digest
            .clone()
            .ok_or(ReplacementError::KernelCutoverRequired)?;
        target.validate_owned()?;
        let fence_digest = active.effective_fence_digest()?;
        state.operation = Some(request.operation_id.clone());
        state.candidate = Some(PreparedCandidate {
            record: target,
            basis: CandidateBasis::CommittedCutover { cutover },
            operation_id: request.operation_id.clone(),
            active_number: active.generation_number(),
            active_fence_digest: fence_digest,
        });
        Ok(RollbackArmed {
            operation_id: request.operation_id.clone(),
            current_generation: request.expected_current,
            target_generation: request.target_generation,
            cutover_digest,
        })
    }

    /// Completes the rollback as the second single compare-and-swap of the
    /// admission target.
    ///
    /// Under the same lock and in the same order as [`Self::switch`], this
    /// rechecks operation ownership, that the drain was armed by this same
    /// operation, that the expected current generation and the fence digest
    /// still match what arming observed, that the restore target equals the
    /// expected restore generation and is still the exact retained record, and
    /// that the generation being retired has no unresolved call. It then
    /// retains the generation being retired through the same bounded
    /// [`Self::retain_old`] a switch uses, records the sealed
    /// [`RollbackReceipt`] on the shared receipt chain, and leaves the call
    /// history untouched: all new-call history survives the rollback.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the operation, target, drain, or
    /// expectation does not validate, when the generation being retired still
    /// has unresolved calls, or when bounded retention cannot admit the retired
    /// generation. A mid-operation failure restores the pre-call state, so a
    /// failure can never leave `active` pointing at a generation with neither an
    /// operation nor a drain.
    pub fn complete_rollback(
        &self,
        operation_id: &str,
        expected_current: u64,
        expected_restore: u64,
    ) -> Result<RollbackReceipt, ReplacementError> {
        check_text(operation_id, "replacement.operation_id")?;
        let mut state = self.lock_state()?;
        state.check_rollback(operation_id, expected_current, expected_restore)?;
        state.commit_rollback(operation_id, expected_current, expected_restore)
    }

    /// Reconciles an unknown switch to exactly one observed active generation
    /// instead of a blind rollback. The observation must name the switch
    /// operation and agree with its new generation.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for unknown operations or disagreeing
    /// observations.
    pub fn reconcile_unknown(
        &self,
        observed: &ObservedGeneration,
    ) -> Result<ReconcileReceipt, ReplacementError> {
        check_text(&observed.operation_id, "replacement.operation_id")?;
        let mut state = self.lock_state()?;
        let Some(switch) = state
            .switch_log
            .iter()
            .find(|receipt| receipt.operation_id == observed.operation_id)
            .cloned()
        else {
            return Err(ReplacementError::UnknownOperation);
        };
        if switch.new_generation != observed.observed_active {
            return Err(ReplacementError::ObservedActiveMismatch);
        }
        let sequence = state.next_sequence()?;
        let prev = state.chain_prev();
        let receipt = seal_reconcile_receipt(sequence, observed, &prev)?;
        let adoption_matches = state
            .adoption
            .as_ref()
            .is_some_and(|adoption| adoption.operation_id == observed.operation_id);
        let active_matches = state
            .active
            .as_ref()
            .is_some_and(|active| active.generation_number() == observed.observed_active);
        if let Some(adoption) = state
            .adoption
            .as_mut()
            .filter(|_| adoption_matches && active_matches)
        {
            adoption.confirmed = true;
        }
        if state.reconcile_log.len() >= MAX_RECEIPTS {
            state.reconcile_log.pop_front();
        }
        state.reconcile_log.push_back(receipt.clone());
        state.chain_head = Some(receipt.receipt_digest.clone());
        Ok(receipt)
    }

    /// Disposes a retained generation. Referenced generations (active,
    /// candidate, or pending slots) and generations with open call leases are
    /// never disposed; a lost lease therefore blocks retirement.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the generation is referenced, leases are
    /// open, or nothing retained carries that number.
    pub fn dispose_generation(&self, generation: u64) -> Result<(), ReplacementError> {
        let mut state = self.lock_state()?;
        if state
            .active
            .as_ref()
            .is_some_and(|active| active.generation_number() == generation)
            || state.referenced_elsewhere(generation)
        {
            return Err(ReplacementError::ReferencedGeneration);
        }
        if state
            .inflight
            .values()
            .any(|lease| lease.accepted_generation == generation)
        {
            return Err(ReplacementError::LeaseUnresolved);
        }
        if state.quarantined.contains_key(&generation) {
            return Err(ReplacementError::ReferencedGeneration);
        }
        if state.retained.remove(&generation).is_none() {
            return Err(ReplacementError::UnknownGeneration);
        }
        Ok(())
    }

    /// Moves a retained generation into explicit bounded quarantine with
    /// evidence instead of forgetting it. Referenced or lease-bound
    /// generations cannot be quarantined.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the generation is referenced, leases are
    /// open, nothing retained carries that number, or quarantine is full.
    pub fn quarantine_generation(
        &self,
        generation: u64,
        evidence: &Sha256Digest,
    ) -> Result<(), ReplacementError> {
        let mut state = self.lock_state()?;
        if state
            .active
            .as_ref()
            .is_some_and(|active| active.generation_number() == generation)
            || state.referenced_elsewhere(generation)
        {
            return Err(ReplacementError::ReferencedGeneration);
        }
        if state
            .inflight
            .values()
            .any(|lease| lease.accepted_generation == generation)
        {
            return Err(ReplacementError::LeaseUnresolved);
        }
        let Some(record) = state.retained.remove(&generation) else {
            return Err(ReplacementError::UnknownGeneration);
        };
        if state.quarantined.len() >= MAX_QUARANTINED_GENERATIONS {
            state.retained.insert(generation, record);
            return Err(ReplacementError::QuarantineFull);
        }
        state.quarantined.insert(
            generation,
            QuarantinedGeneration {
                record,
                evidence: evidence.clone(),
            },
        );
        Ok(())
    }

    /// Verifies call invariants: every tracked in-flight call names the
    /// current admission target exactly once, no call is both tracked and
    /// recorded as history, and every history entry carries a final
    /// terminal/unknown disposition.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::InvariantViolation`] on any breach.
    pub fn verify_call_invariants(&self) -> Result<(), ReplacementError> {
        let state = self.lock_state()?;
        let active_number = state.active.as_ref().map(ActiveBinding::generation_number);
        for lease in state.inflight.values() {
            if active_number.is_none_or(|active| lease.accepted_generation != active) {
                return Err(ReplacementError::InvariantViolation(
                    "call-acceptance-mismatch".to_owned(),
                ));
            }
            if state
                .history
                .iter()
                .any(|entry| entry.call_id == lease.call_id)
            {
                return Err(ReplacementError::InvariantViolation(
                    "call-tracked-and-recorded".to_owned(),
                ));
            }
        }
        if state
            .history
            .iter()
            .any(|entry| entry.disposition == CallDisposition::Accepted)
        {
            return Err(ReplacementError::InvariantViolation(
                "history-without-disposition".to_owned(),
            ));
        }
        Ok(())
    }

    /// Verifies that one replacement operation produced at most one
    /// linearizable switch receipt: each replacement has one switch or an
    /// exact no-switch/unknown outcome.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::InvariantViolation`] when an operation
    /// switched more than once.
    pub fn verify_switch_uniqueness(&self, operation_id: &str) -> Result<(), ReplacementError> {
        let state = self.lock_state()?;
        let mut switches = 0_usize;
        for receipt in &state.switch_log {
            if receipt.operation_id == operation_id {
                switches += 1;
            }
        }
        if switches > 1 {
            return Err(ReplacementError::InvariantViolation(
                "operation-switched-twice".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the number of tracked in-flight calls.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::CoordinatorUnavailable`] when the lock is
    /// unavailable.
    pub fn inflight_count(&self) -> Result<usize, ReplacementError> {
        Ok(self.lock_state()?.inflight.len())
    }

    /// Returns the number of retained generations.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::CoordinatorUnavailable`] when the lock is
    /// unavailable.
    pub fn retained_count(&self) -> Result<usize, ReplacementError> {
        Ok(self.lock_state()?.retained.len())
    }

    /// Returns retained switch, rollback, and reconciliation receipt counts.
    /// A rollback receipt exists only after an owner-committed newer-epoch
    /// cutover armed and completed one, so this count is bounded evidence of
    /// executed cutovers rather than of proposals.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::CoordinatorUnavailable`] when the lock is
    /// unavailable.
    pub fn receipt_count(&self) -> Result<usize, ReplacementError> {
        let state = self.lock_state()?;
        Ok(state.switch_log.len() + state.rollback_log.len() + state.reconcile_log.len())
    }

    /// Returns the number of terminal/unknown call history entries.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::CoordinatorUnavailable`] when the lock is
    /// unavailable.
    pub fn history_len(&self) -> Result<usize, ReplacementError> {
        Ok(self.lock_state()?.history.len())
    }

    /// Returns the number of generations held in bounded quarantine.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::CoordinatorUnavailable`] when the lock is
    /// unavailable.
    pub fn quarantined_count(&self) -> Result<usize, ReplacementError> {
        Ok(self.lock_state()?.quarantined.len())
    }

    /// Returns the quarantine evidence digest for a quarantined generation, or
    /// `None` when nothing is quarantined under that number.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::CoordinatorUnavailable`] when the lock is
    /// unavailable.
    pub fn quarantined_evidence(
        &self,
        generation: u64,
    ) -> Result<Option<Sha256Digest>, ReplacementError> {
        Ok(self
            .lock_state()?
            .quarantined
            .get(&generation)
            .map(|quarantined| quarantined.evidence.clone()))
    }

    /// Returns the artifact digest of a quarantined generation, or `None` when
    /// nothing is quarantined under that number.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::CoordinatorUnavailable`] when the lock is
    /// unavailable.
    pub fn quarantined_artifact(
        &self,
        generation: u64,
    ) -> Result<Option<Sha256Digest>, ReplacementError> {
        Ok(self
            .lock_state()?
            .quarantined
            .get(&generation)
            .map(|quarantined| quarantined.record.artifact_digest.clone()))
    }

    /// Returns the current receipt-chain head digest, if any receipt exists.
    ///
    /// # Errors
    ///
    /// Returns [`ReplacementError::CoordinatorUnavailable`] when the lock is
    /// unavailable.
    pub fn receipt_chain_head(&self) -> Result<Option<Sha256Digest>, ReplacementError> {
        Ok(self.lock_state()?.chain_head.clone())
    }

    /// Pure rehydration over an owner-supplied lifecycle log. Entries are
    /// reconciled under their exact sequence (duplicate delivery replays,
    /// reordered observations sort into sequence); gaps and a retired active
    /// generation derive `Unknown`, never a guess. Durable publication
    /// without a preceding local switch is rejected as fabricated.
    ///
    /// # Errors
    ///
    /// Returns a typed failure on conflicting same-sequence entries, broken
    /// predecessor linkage, or fabricated durability. This function performs
    /// no I/O.
    pub fn rehydrate_replacement(
        entries: &[LifecycleLogEntry],
    ) -> Result<RehydratedState, ReplacementError> {
        let mut ordered: Vec<LifecycleLogEntry> = entries.to_vec();
        ordered.sort_by_key(|entry| entry.sequence);
        let mut deduped: Vec<LifecycleLogEntry> = Vec::with_capacity(ordered.len());
        for entry in ordered {
            match deduped.last() {
                Some(previous) if previous.sequence == entry.sequence => {
                    if *previous != entry {
                        return Err(ReplacementError::LogSequenceConflict);
                    }
                }
                _ => deduped.push(entry),
            }
        }
        let mut active: Option<(u64, Sha256Digest)> = None;
        let mut activated: BTreeSet<u64> = BTreeSet::new();
        let mut gap = false;
        let mut retired_active = false;
        let mut expected: Option<u64> = None;
        for entry in &deduped {
            if expected.is_some_and(|next| entry.sequence != next) {
                gap = true;
            }
            expected = Some(entry.sequence.saturating_add(1));
            match entry.kind {
                LifecycleEventKind::Prepared | LifecycleEventKind::DrainBegan => {}
                LifecycleEventKind::Switched => {
                    let linked = match active.as_ref() {
                        Some((previous, _)) => entry.previous_active == Some(*previous),
                        None => entry.previous_active.is_none(),
                    };
                    if !linked {
                        return Err(ReplacementError::PredecessorMismatch);
                    }
                    active = Some((entry.generation, entry.artifact.clone()));
                    activated.insert(entry.generation);
                    retired_active = false;
                }
                LifecycleEventKind::RollbackCompleted => {
                    let linked = active
                        .as_ref()
                        .is_some_and(|(previous, _)| entry.previous_active == Some(*previous));
                    if !linked {
                        return Err(ReplacementError::PredecessorMismatch);
                    }
                    active = Some((entry.generation, entry.artifact.clone()));
                    activated.insert(entry.generation);
                    retired_active = false;
                }
                LifecycleEventKind::Retired => {
                    if active
                        .as_ref()
                        .is_some_and(|(current, _)| *current == entry.generation)
                    {
                        active = None;
                        retired_active = true;
                    }
                }
                LifecycleEventKind::ExternallyPublished => {
                    if !activated.contains(&entry.generation) {
                        return Err(ReplacementError::FabricatedDurability);
                    }
                }
            }
        }
        if gap || retired_active {
            Ok(RehydratedState::Unknown)
        } else if let Some((generation, artifact)) = active {
            Ok(RehydratedState::Active {
                generation,
                artifact,
            })
        } else {
            Ok(RehydratedState::NoActive)
        }
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, CoordinatorState>, ReplacementError> {
        self.state
            .lock()
            .map_err(|_| ReplacementError::CoordinatorUnavailable)
    }

    fn release_operation(&self, operation_id: &str) {
        let Ok(mut state) = self.lock_state() else {
            return;
        };
        if state.holds_operation(operation_id) {
            state.operation = None;
        }
    }

    fn claim_operation_for_prepare(
        &self,
        request: &PrepareRequest,
    ) -> Result<ActiveSnapshot, ReplacementError> {
        let mut state = self.lock_state()?;
        if state.operation.is_some() {
            return Err(ReplacementError::ReplacementInProgress);
        }
        let Some(active) = state.active.clone() else {
            return Err(ReplacementError::NoActiveGeneration);
        };
        if active.generation_number() != request.expected_active {
            return Err(ReplacementError::StaleExpectedGeneration);
        }
        check_compatible(&active.record, &request.candidate.record)?;
        let fence_digest = active.effective_fence_digest()?;
        state.operation = Some(request.operation_id.clone());
        Ok(ActiveSnapshot {
            number: active.generation_number(),
            fence_digest,
        })
    }

    fn store_candidate(
        &self,
        request: &PrepareRequest,
        snapshot: &ActiveSnapshot,
        evidence: &ReadinessEvidence,
    ) -> Result<PreparedSummary, ReplacementError> {
        if !evidence.success {
            self.release_operation(&request.operation_id);
            return Err(ReplacementError::ReadinessFailed);
        }
        let candidate_number = request.candidate.record.generation_number();
        if evidence.generation != candidate_number {
            self.release_operation(&request.operation_id);
            return Err(ReplacementError::InvalidGeneration(
                "readiness-generation-mismatch".to_owned(),
            ));
        }
        let mut state = self.lock_state()?;
        if !state.holds_operation(&request.operation_id) {
            return Err(ReplacementError::UnknownOperation);
        }
        state.candidate = Some(PreparedCandidate {
            record: request.candidate.record.clone(),
            basis: CandidateBasis::Probe(evidence.clone()),
            operation_id: request.operation_id.clone(),
            active_number: snapshot.number,
            active_fence_digest: snapshot.fence_digest.clone(),
        });
        Ok(PreparedSummary {
            operation_id: request.operation_id.clone(),
            candidate_generation: candidate_number,
            readiness_digest: evidence.probe_output_digest.clone(),
        })
    }
}

impl Default for GenerationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

struct ActiveSnapshot {
    number: u64,
    fence_digest: Sha256Digest,
}

impl GenerationRecord {
    fn validate_owned(&self) -> Result<(), ReplacementError> {
        if self.generation.artifact_id.as_str() != self.artifact_digest.as_str() {
            return Err(ReplacementError::InvalidGeneration(
                "artifact-binding-mismatch".to_owned(),
            ));
        }
        self.generation
            .validate()
            .map_err(|_| external_contract("module-generation-rejected"))?;
        self.engine
            .validate()
            .map_err(|_| invalid_generation("engine-binding-rejected"))?;
        self.limits
            .validate(&self.artifact_digest)
            .map_err(|_| invalid_generation("limit-envelope-rejected"))?;
        Ok(())
    }
}

impl CoordinatorState {
    fn check_rollback(
        &self,
        operation_id: &str,
        expected_current: u64,
        expected_restore: u64,
    ) -> Result<(), ReplacementError> {
        if !self.holds_operation(operation_id) {
            return Err(ReplacementError::UnknownOperation);
        }
        let Some(candidate) = self.candidate.as_ref() else {
            return Err(ReplacementError::NoPreparedCandidate);
        };
        let Some(cutover) = candidate.basis.committed_cutover() else {
            return Err(ReplacementError::NoArmedRollback);
        };
        if candidate.operation_id != operation_id {
            return Err(ReplacementError::UnknownOperation);
        }
        if self
            .draining
            .as_ref()
            .is_none_or(|drain| drain.operation_id != operation_id)
        {
            return Err(ReplacementError::DrainNotArmed);
        }
        let Some(active) = self.active.as_ref() else {
            return Err(ReplacementError::NoActiveGeneration);
        };
        if active.generation_number() != expected_current
            || active.generation_number() != candidate.active_number
        {
            return Err(ReplacementError::StaleExpectedGeneration);
        }
        if candidate.record.generation_number() != expected_restore {
            return Err(ReplacementError::StaleExpectedGeneration);
        }
        // The pinned owner evidence is re-checked here, at the linearization
        // point, so a rollback is only completed under the exact cutover that
        // armed it. The fence is still the one arming observed (checked
        // immediately below), so the newer-epoch rule is re-evaluated against
        // that same fence.
        check_committed_cutover(cutover, expected_current, expected_restore, active)?;
        let fence_digest = active.effective_fence_digest()?;
        if fence_digest != candidate.active_fence_digest {
            return Err(ReplacementError::StaleExpectedGeneration);
        }
        match self.retained.get(&expected_restore) {
            Some(retained) if retained.artifact_digest == candidate.record.artifact_digest => {}
            Some(_) => return Err(ReplacementError::RollbackPayloadChanged),
            None => return Err(ReplacementError::UnknownGeneration),
        }
        if !self.unresolved_on(active.generation_number()).is_empty() {
            return Err(ReplacementError::DrainUnresolved);
        }
        Ok(())
    }

    fn commit_rollback(
        &mut self,
        operation_id: &str,
        expected_current: u64,
        expected_restore: u64,
    ) -> Result<RollbackReceipt, ReplacementError> {
        let sequence = self.next_sequence()?;
        let Some(candidate) = self.candidate.take() else {
            return Err(ReplacementError::NoPreparedCandidate);
        };
        let Some(previous) = self.active.take() else {
            self.candidate = Some(candidate);
            return Err(ReplacementError::NoActiveGeneration);
        };
        let Some(cutover) = candidate.basis.committed_cutover().cloned() else {
            self.active = Some(previous);
            self.candidate = Some(candidate);
            return Err(ReplacementError::NoArmedRollback);
        };
        let Ok(cutover_digest) = canonical_digest(&cutover) else {
            self.active = Some(previous);
            self.candidate = Some(candidate);
            return Err(external_contract("cutover-seal-failed"));
        };
        if let Err(error) = self.retain_old(previous.record.clone()) {
            self.active = Some(previous);
            self.candidate = Some(candidate);
            return Err(error);
        }
        // The restored generation leaves `retained` as it becomes the active
        // admission target; it is restored here if any later step fails.
        let withdrawn = self.retained.remove(&expected_restore);
        let restored_artifact = candidate.record.artifact_digest.clone();
        // New-call history is never cleared by a rollback.
        let new_calls_retained = self.new_calls_on(expected_current);
        let prev = self.chain_prev();
        let receipt = match seal_rollback_receipt(
            sequence,
            operation_id,
            expected_current,
            expected_restore,
            &restored_artifact,
            &cutover_digest,
            new_calls_retained,
            &prev,
        ) {
            Ok(receipt) => receipt,
            // The admission target has not moved yet, so the whole pre-call
            // state — active generation, pending candidate, and the withdrawn
            // retained record — is restored exactly. Operation, drain, and
            // adoption were never touched.
            Err(error) => {
                if let Some(record) = withdrawn {
                    self.retained.insert(record.generation_number(), record);
                }
                self.active = Some(previous);
                self.candidate = Some(candidate);
                return Err(error);
            }
        };
        self.active = Some(ActiveBinding {
            record: candidate.record,
            rollback_cutover: Some(cutover),
        });
        self.adoption = Some(AdoptionInfo {
            operation_id: operation_id.to_owned(),
            calls_accepted_since: 0,
            confirmed: false,
        });
        self.draining = None;
        self.operation = None;
        if self.rollback_log.len() >= MAX_RECEIPTS {
            self.rollback_log.pop_front();
        }
        self.rollback_log.push_back(receipt.clone());
        self.chain_head = Some(receipt.receipt_digest.clone());
        Ok(receipt)
    }

    /// Counts the recorded new-call history on one generation, saturating
    /// rather than wrapping if a bounded history ever exceeded `u64::MAX`.
    fn new_calls_on(&self, generation: u64) -> u64 {
        u64::try_from(
            self.history
                .iter()
                .filter(|entry| entry.generation == generation)
                .count(),
        )
        .unwrap_or(u64::MAX)
    }

    fn check_switch(&self, request: &SwitchRequest) -> Result<(), ReplacementError> {
        if !self.holds_operation(&request.operation_id) {
            return Err(ReplacementError::UnknownOperation);
        }
        let Some(candidate) = self.candidate.as_ref() else {
            return Err(ReplacementError::NoPreparedCandidate);
        };
        if candidate.operation_id != request.operation_id {
            return Err(ReplacementError::UnknownOperation);
        }
        if self
            .draining
            .as_ref()
            .is_none_or(|drain| drain.operation_id != request.operation_id)
        {
            return Err(ReplacementError::DrainNotArmed);
        }
        let Some(active) = self.active.as_ref() else {
            return Err(ReplacementError::NoActiveGeneration);
        };
        if active.generation_number() != request.expected_active
            || active.generation_number() != candidate.active_number
        {
            return Err(ReplacementError::StaleExpectedGeneration);
        }
        let fence_digest = active.effective_fence_digest()?;
        if fence_digest != candidate.active_fence_digest {
            return Err(ReplacementError::StaleExpectedGeneration);
        }
        match &candidate.basis {
            CandidateBasis::Probe(evidence) => {
                if evidence.generation != candidate.record.generation_number() || !evidence.success
                {
                    return Err(ReplacementError::InvalidGeneration(
                        "readiness-not-retained".to_owned(),
                    ));
                }
            }
            // A rollback target is admitted by the owner-committed cutover, not
            // by a forward probe, so it has no forward switch to perform.
            CandidateBasis::CommittedCutover { .. } => {
                return Err(ReplacementError::RollbackCutoverPending);
            }
        }
        if !self.unresolved_on(active.generation_number()).is_empty() {
            return Err(ReplacementError::DrainUnresolved);
        }
        Ok(())
    }

    fn commit_switch(
        &mut self,
        request: &SwitchRequest,
    ) -> Result<SwitchReceipt, ReplacementError> {
        let Some(candidate) = self.candidate.take() else {
            return Err(ReplacementError::NoPreparedCandidate);
        };
        let Some(previous) = self.active.take() else {
            self.candidate = Some(candidate);
            return Err(ReplacementError::NoActiveGeneration);
        };
        if let Err(error) = self.retain_old(previous.record.clone()) {
            self.active = Some(previous);
            self.candidate = Some(candidate);
            return Err(error);
        }
        let new_number = candidate.record.generation_number();
        let new_artifact = candidate.record.artifact_digest.clone();
        self.active = Some(ActiveBinding::initial(candidate.record));
        self.adoption = Some(AdoptionInfo {
            operation_id: request.operation_id.clone(),
            calls_accepted_since: 0,
            confirmed: false,
        });
        self.draining = None;
        self.operation = None;
        let sequence = self.next_sequence()?;
        let prev = self.chain_prev();
        let empty: Vec<String> = Vec::new();
        let inflight_digest =
            canonical_digest(&empty).map_err(|_| external_contract("receipt-seal-failed"))?;
        let receipt = seal_switch_receipt(
            sequence,
            &request.operation_id,
            previous.generation_number(),
            new_number,
            &previous.record.artifact_digest,
            &new_artifact,
            &inflight_digest,
            &prev,
        )?;
        if self.switch_log.len() >= MAX_RECEIPTS {
            self.switch_log.pop_front();
        }
        self.switch_log.push_back(receipt.clone());
        self.chain_head = Some(receipt.receipt_digest.clone());
        Ok(receipt)
    }
}

fn check_text(value: &str, field: &'static str) -> Result<(), ReplacementError> {
    crate::validate_text(value, field).map_err(|_| ReplacementError::InvalidField(field.to_owned()))
}

fn invalid_generation(code: &'static str) -> ReplacementError {
    ReplacementError::InvalidGeneration(code.to_owned())
}

fn external_contract(code: &'static str) -> ReplacementError {
    ReplacementError::ExternalContract(code.to_owned())
}

fn check_compatible(
    old: &GenerationRecord,
    new: &GenerationRecord,
) -> Result<(), ReplacementError> {
    // Forward replacements only. A rollback restores a retained generation,
    // which is by definition older; `arm_rollback` uses
    // `check_compatible_fields` for exactly that reason.
    if new.generation_number() <= old.generation_number() {
        return Err(ReplacementError::IncompatibleCandidate(
            "generation-regression".to_owned(),
        ));
    }
    check_compatible_fields(old, new)
}

/// Validates the owner-committed cutover that authorises a rollback restore and
/// returns the exact receipt to pin on the armed candidate.
///
/// `EpochId` is not nameable from this crate (`eliot-runtime-contracts` keeps
/// it a private import), so the lineage and sequence are compared through the
/// public fields of the value, exactly as
/// `eliot_contracts::EpochId::is_same_authority` defines exact authority
/// (lineage AND sequence; equal sequences from different lineages are
/// unrelated). No new dependency is introduced for this.
fn check_rollback_cutover(
    request: &RollbackRequest,
    active: &ActiveBinding,
) -> Result<GenerationCutoverReceipt, ReplacementError> {
    let (Some(cutover), Some(expected_digest)) = (&request.cutover, &request.cutover_digest) else {
        return Err(ReplacementError::KernelCutoverRequired);
    };
    let digest = canonical_digest(cutover).map_err(|_| external_contract("cutover-seal-failed"))?;
    if digest != *expected_digest {
        return Err(ReplacementError::RollbackPayloadChanged);
    }
    check_committed_cutover(
        cutover,
        request.expected_current,
        request.target_generation,
        active,
    )?;
    Ok(cutover.clone())
}

/// The owner-evidence half of a rollback gate, shared by arming and completion
/// so both linearization points apply exactly the same rules.
///
/// The receipt must be a `Completed` cutover (a
/// `FAILED_REQUIRES_FORWARD_CUTOVER` receipt is the owner demanding forward
/// repair, not permission to restore a route), must name exactly
/// `expected_current` as the generation being retired and `expected_restore` as
/// the restored one, and must carry an authority epoch in the retired
/// generation's own fence lineage with a strictly greater sequence. An old
/// epoch is never reactivated and a foreign lineage is never ordered against
/// the active authority.
fn check_committed_cutover(
    cutover: &GenerationCutoverReceipt,
    expected_current: u64,
    expected_restore: u64,
    retired: &ActiveBinding,
) -> Result<(), ReplacementError> {
    cutover
        .validate()
        .map_err(|_| external_contract("cutover-receipt-rejected"))?;
    if !matches!(cutover.state, GenerationCutoverState::Completed) {
        return Err(external_contract("cutover-not-completed"));
    }
    if cutover.new_generation.value() != expected_restore {
        return Err(external_contract("cutover-new-generation-mismatch"));
    }
    if cutover
        .old_generation
        .is_none_or(|retired| retired.value() != expected_current)
    {
        return Err(external_contract("cutover-old-generation-mismatch"));
    }
    let supplied = &cutover.authority_epoch;
    let (lineage_id, sequence) = match retired.rollback_cutover.as_ref() {
        Some(current) => (
            &current.authority_epoch.lineage_id,
            current.authority_epoch.sequence,
        ),
        None => (
            &retired
                .record
                .generation
                .state_fence
                .authority_epoch
                .lineage_id,
            retired
                .record
                .generation
                .state_fence
                .authority_epoch
                .sequence,
        ),
    };
    if supplied.lineage_id != *lineage_id {
        return Err(ReplacementError::RollbackEpochNotNewer);
    }
    if supplied.sequence <= sequence {
        return Err(ReplacementError::OldEpochReactivation);
    }
    Ok(())
}

fn check_compatible_fields(
    old: &GenerationRecord,
    new: &GenerationRecord,
) -> Result<(), ReplacementError> {
    if old.module_id() != new.module_id() {
        return Err(ReplacementError::IncompatibleCandidate(
            "module-mismatch".to_owned(),
        ));
    }
    if old.world != new.world {
        return Err(ReplacementError::IncompatibleCandidate(
            "world-mismatch".to_owned(),
        ));
    }
    if old.abi_digest != new.abi_digest {
        if old.component_version == new.component_version {
            return Err(ReplacementError::IncompatibleCandidate(
                "abi-drift".to_owned(),
            ));
        }
        return Err(ReplacementError::IncompatibleCandidate(
            "abi-mismatch".to_owned(),
        ));
    }
    if old.kit_digest != new.kit_digest {
        return Err(ReplacementError::IncompatibleCandidate(
            "kit-mismatch".to_owned(),
        ));
    }
    if old.engine.implementation_id != new.engine.implementation_id {
        return Err(ReplacementError::IncompatibleCandidate(
            "engine-mismatch".to_owned(),
        ));
    }
    if !new.observed_imports.is_subset(&old.observed_imports) {
        return Err(ReplacementError::IncompatibleCandidate(
            "capability-expansion".to_owned(),
        ));
    }
    if !limits_narrower(old, new) {
        return Err(ReplacementError::IncompatibleCandidate(
            "limit-widening".to_owned(),
        ));
    }
    match (&old.state_migration, &new.state_migration) {
        (StateMigration::Stateless, _)
        | (StateMigration::Reversible { .. }, StateMigration::Reversible { .. }) => Ok(()),
        (StateMigration::Reversible { .. }, StateMigration::Stateless) => Err(
            ReplacementError::IncompatibleCandidate("state-migration".to_owned()),
        ),
    }
}

fn limits_narrower(old: &GenerationRecord, new: &GenerationRecord) -> bool {
    let old_limits = &old.limits;
    let new_limits = &new.limits;
    new_limits.max_input_bytes <= old_limits.max_input_bytes
        && new_limits.max_output_bytes <= old_limits.max_output_bytes
        && new_limits.max_host_calls <= old_limits.max_host_calls
        && new_limits.max_fuel <= old_limits.max_fuel
        && new_limits.max_memory_bytes <= old_limits.max_memory_bytes
        && new_limits.max_table_elements <= old_limits.max_table_elements
        && new_limits.max_instances <= old_limits.max_instances
        && new_limits.max_stack_bytes <= old_limits.max_stack_bytes
        && new_limits.wall_deadline_ms <= old_limits.wall_deadline_ms
        && new_limits.epoch.deadline_ticks <= old_limits.epoch.deadline_ticks
        && new_limits.epoch.cancellation == old_limits.epoch.cancellation
        && new_limits.artifact_access.max_reads <= old_limits.artifact_access.max_reads
        && new_limits.artifact_access.max_bytes <= old_limits.artifact_access.max_bytes
        && non_artifact_digests(new_limits, &new.artifact_digest)
            .is_subset(&non_artifact_digests(old_limits, &old.artifact_digest))
}

/// Digests admitted beyond the generation's own artifact: the only
/// artifact-access surface that must not widen across a replacement. Each
/// generation necessarily admits its own (rotating) artifact — structural
/// validation already requires that membership — so the raw allowed sets are
/// compared modulo the rotation. A candidate admitting any foreign digest the
/// old generation did not admit still fails as widening.
fn non_artifact_digests(
    limits: &InvocationLimits,
    artifact: &Sha256Digest,
) -> BTreeSet<Sha256Digest> {
    limits
        .artifact_access
        .allowed_digests
        .iter()
        .filter(|digest| *digest != artifact)
        .cloned()
        .collect()
}

fn genesis_digest() -> Sha256Digest {
    Sha256Digest::of_bytes(b"eliot-wasm-runtime/replacement/v1")
}

#[derive(Serialize)]
struct SwitchSeal<'a> {
    sequence: u64,
    operation_id: &'a str,
    old_generation: u64,
    new_generation: u64,
    old_artifact: &'a Sha256Digest,
    new_artifact: &'a Sha256Digest,
    inflight_at_switch: u64,
    inflight_digest: &'a Sha256Digest,
    prev_receipt_digest: &'a Sha256Digest,
}

#[derive(Serialize)]
struct ReconcileSeal<'a> {
    sequence: u64,
    operation_id: &'a str,
    observed_active: u64,
    evidence: &'a Sha256Digest,
    prev_receipt_digest: &'a Sha256Digest,
}

#[allow(clippy::too_many_arguments)]
fn seal_switch_receipt(
    sequence: u64,
    operation_id: &str,
    old_generation: u64,
    new_generation: u64,
    old_artifact: &Sha256Digest,
    new_artifact: &Sha256Digest,
    inflight_digest: &Sha256Digest,
    prev: &Sha256Digest,
) -> Result<SwitchReceipt, ReplacementError> {
    let seal = SwitchSeal {
        sequence,
        operation_id,
        old_generation,
        new_generation,
        old_artifact,
        new_artifact,
        inflight_at_switch: 0,
        inflight_digest,
        prev_receipt_digest: prev,
    };
    let receipt_digest =
        canonical_digest(&seal).map_err(|_| external_contract("receipt-seal-failed"))?;
    Ok(SwitchReceipt {
        sequence,
        operation_id: operation_id.to_owned(),
        old_generation,
        new_generation,
        old_artifact: old_artifact.clone(),
        new_artifact: new_artifact.clone(),
        inflight_at_switch: 0,
        inflight_digest: inflight_digest.clone(),
        prev_receipt_digest: prev.clone(),
        receipt_digest,
        durable_published: false,
        external_evidence: None,
    })
}

#[derive(Serialize)]
struct RollbackSeal<'a> {
    sequence: u64,
    operation_id: &'a str,
    from_generation: u64,
    restored_generation: u64,
    restored_artifact: &'a Sha256Digest,
    cutover_digest: &'a Sha256Digest,
    new_calls_retained: u64,
    prev_receipt_digest: &'a Sha256Digest,
}

/// Seals over exactly the fields [`RollbackReceipt`] declares, so the receipt
/// and its chain link are one digest in the same shape as the switch and
/// reconcile seals. It attests to the local compare-and-swap only; the durable
/// cutover is proved by the [`GenerationCutoverReceipt`] the request supplied.
#[allow(clippy::too_many_arguments)]
fn seal_rollback_receipt(
    sequence: u64,
    operation_id: &str,
    from_generation: u64,
    restored_generation: u64,
    restored_artifact: &Sha256Digest,
    cutover_digest: &Sha256Digest,
    new_calls_retained: u64,
    prev: &Sha256Digest,
) -> Result<RollbackReceipt, ReplacementError> {
    let seal = RollbackSeal {
        sequence,
        operation_id,
        from_generation,
        restored_generation,
        restored_artifact,
        cutover_digest,
        new_calls_retained,
        prev_receipt_digest: prev,
    };
    let receipt_digest =
        canonical_digest(&seal).map_err(|_| external_contract("receipt-seal-failed"))?;
    Ok(RollbackReceipt {
        sequence,
        operation_id: operation_id.to_owned(),
        from_generation,
        restored_generation,
        restored_artifact: restored_artifact.clone(),
        cutover_digest: cutover_digest.clone(),
        new_calls_retained,
        prev_receipt_digest: prev.clone(),
        receipt_digest,
    })
}

fn seal_reconcile_receipt(
    sequence: u64,
    observed: &ObservedGeneration,
    prev: &Sha256Digest,
) -> Result<ReconcileReceipt, ReplacementError> {
    let seal = ReconcileSeal {
        sequence,
        operation_id: &observed.operation_id,
        observed_active: observed.observed_active,
        evidence: &observed.evidence,
        prev_receipt_digest: prev,
    };
    let receipt_digest =
        canonical_digest(&seal).map_err(|_| external_contract("receipt-seal-failed"))?;
    Ok(ReconcileReceipt {
        sequence,
        operation_id: observed.operation_id.clone(),
        observed_active: observed.observed_active,
        evidence: observed.evidence.clone(),
        prev_receipt_digest: prev.clone(),
        receipt_digest,
    })
}
