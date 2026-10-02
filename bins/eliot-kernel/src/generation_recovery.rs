//! Kernel ORS generation recovery and cutover persistence.
//!
//! Owns bounded reconstruction of the generation router from committed ORS
//! cutovers and the persist-then-publish closure that synchronizes the Kernel
//! service epoch and daemon handshake generation/state fence.
//!
//! Architecture: A13.2 Kernel и failure domains; A13.3 Module supervision и Doctor; A13.6 Operational Recovery State; ARCH-RES-01 Fail locally, recover globally; ARCH-RES-03 Restore/migration cannot resurrect invalid state; ARCH-RES-04 Degradation is visible and local
//! Implementation: I4.5 Generation vector and State Fence; I14.14 Module hot replacement; I14.21 Unknown commit recovery; P.4 Operational Recovery State boundary; I2.23 Capability-family topology and crate extraction decisions
//! Forbidden authority: must not interpret semantic content, become a second generation authority, publish an uncommitted route, or bypass the ORS cutover record, authority epoch, and handshake fence.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_contracts::StateFence;
use eliot_ipc::ServerHandshakePolicy;
use eliot_kernel_core::{
    CompatibilityMismatch, CutoverDecision, DurableCompatibilityState, GenerationRoute,
    GenerationRouter, RouteScope, admit_rollback, restore_recorded_evidence,
};
use eliot_kernel_service::KernelService;
use eliot_ors::{CutoverRouteSnapshot, CutoverRouteTable, OrsError, RedbRecoveryStore};
use eliot_runtime_contracts::{
    GenerationCutoverRecord as RuntimeGenerationCutoverRecord, GenerationCutoverState,
};

use crate::{PROTOCOL_VERSION, SERVICE_NAME};

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// F-LOG-KERNEL-4 (#903 slice B): recovery and cutover-persistence boundary
/// observations.
///
/// Observation only, via #895's facade: fixed `kernel.recovery.*` event names
/// plus a bounded stable outcome. Never carries cutover identities, digests,
/// epochs, scopes, generations, or owner error strings (I15.4, I07.20).
/// Terminal ownership stays with the calling gateways: a failed `recover`
/// replay is terminal-mapped by the composition build owner, and a failed
/// `persist_and_publish` is fenced and terminal-mapped by the cutover gateway
/// owner in `generation_control.rs`. Subordinate phases correlate here
/// without duplicate failure claims, and no observation mutates the router,
/// the service epoch, the handshake policy, or the ORS record.
fn observe_recovery(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "generation recovery observation"
    );
}

/// F-LOG-KERNEL-4 (#903 W7): cutover-scoped persistence observations.
///
/// Same #895-only shape as [`observe_recovery`] plus the cutover call's own
/// validated operation identity (already echoed on the authenticated
/// `GenerationCutoverOutcome` reply; I15.4, I07.20, W6), policy-screened and
/// bounded by `bound_field` before formatting. Deferred phase records of
/// concurrent cutovers correlate by identity with no dedup cache, no new
/// probe, and no lock-held emission.
fn observe_recovery_cutover(event: &'static str, outcome: &'static str, cutover_id: &str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    let cutover_bound = bound_field(cutover_id);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        cutover_id = cutover_bound.text(),
        "generation recovery observation"
    );
}

#[derive(Clone, Copy)]
enum HandshakePolicyObservation {
    Projected,
    Absent,
}

impl HandshakePolicyObservation {
    fn emit(self) {
        match self {
            Self::Projected => {
                observe_recovery("kernel.recovery.handshake_projected", "success");
            }
            Self::Absent => observe_recovery("kernel.recovery.handshake_absent", "absent"),
        }
    }

    /// Cutover-scoped handshake observation: the same subordinate record,
    /// correlated to its cutover call by the validated operation identity (W7).
    fn emit_for_cutover(self, cutover_id: &str) {
        match self {
            Self::Projected => {
                observe_recovery_cutover(
                    "kernel.recovery.handshake_projected",
                    "success",
                    cutover_id,
                );
            }
            Self::Absent => {
                observe_recovery_cutover("kernel.recovery.handshake_absent", "absent", cutover_id);
            }
        }
    }
}

/// Fixed-size record of the persistence phases reached by one cutover.
///
/// The owner performs each phase synchronously while it holds the generation,
/// service, policy, and poison guards. The caller emits this record only after
/// those guards have been released, preserving the phase order without adding
/// a queue or another state owner. Every emitted record carries the cutover's
/// own validated operation identity, so concurrent cutovers correlate by
/// identity as well as by order (W7).
#[derive(Clone, Copy, Default)]
pub(crate) struct PersistAndPublishObservations {
    cutover_staged: bool,
    cutover_committed: bool,
    handshake_policy: Option<HandshakePolicyObservation>,
    cutover_applied: bool,
}

pub(crate) struct PersistAndPublishResult {
    pub(crate) result: Result<(), String>,
    pub(crate) observations: PersistAndPublishObservations,
}

impl PersistAndPublishObservations {
    pub(crate) fn emit(self, succeeded: bool, cutover_id: &str) {
        observe_recovery_cutover("kernel.recovery.persist_requested", "attempt", cutover_id);
        if self.cutover_staged {
            observe_recovery_cutover("kernel.recovery.cutover_staged", "success", cutover_id);
        }
        if self.cutover_committed {
            observe_recovery_cutover("kernel.recovery.cutover_committed", "success", cutover_id);
        }
        if let Some(observation) = self.handshake_policy {
            observation.emit_for_cutover(cutover_id);
        }
        if self.cutover_applied {
            observe_recovery_cutover("kernel.recovery.cutover_applied", "success", cutover_id);
        }
        if succeeded {
            observe_recovery_cutover("kernel.recovery.persist_completed", "success", cutover_id);
        } else {
            observe_recovery_cutover("kernel.recovery.persist_failed", "rejected", cutover_id);
        }
    }
}

pub(crate) struct OrsGenerationCoordinator {
    pub(crate) ors: Arc<RedbRecoveryStore>,
    /// Committed I14.14 route ownership rebuilt during startup recovery.
    /// Admission consumers must supply the canonical route-scope hash; this
    /// table never derives one from a request's partial route fields.
    pub(crate) cutover_routes: CutoverRouteTable,
}

/// The current durable compatibility state the Kernel is running under, used
/// to gate every restored route as a rollback (I1.12, issue #1890 W4).
///
/// Built from the SAME live values the runtime handshake binds
/// (`frame_dispatch::runtime_module_compatibility`) and the
/// candidate-activation
/// gate compares against (`compatibility_gate::durable_compatibility_state`), so
/// the rollback gate and the activation handshake are compared against one
/// durable state rather than three independently derived projections. Nothing is
/// invented and no evidence is carried over from a previous process.
///
/// It is the state for EVERY route, so it deliberately carries no Store API
/// contract-set digest. The one receiver-held operand on this path is bound per
/// route scope in [`store_bridge_durable_compatibility_state`], immediately
/// before the comparison, for the store-bridge route alone.
fn current_durable_compatibility_state(
    service: &KernelService,
) -> Result<DurableCompatibilityState, String> {
    super::compatibility_gate::durable_compatibility_state(&service.authority_epoch())
}

/// The receiver-held Store API contract-set digest, bound for the ONE route scope
/// that has a receiver side for that comparison.
///
/// `DurableCompatibilityState` holds no Store API digest by default, and that
/// default is load-bearing rather than incidental: `admit_rollback` refuses the
/// `(receiver holds one, record holds none)` pair, so binding this value for
/// every route would refuse each non-store generation on the "recorded evidence
/// carries no Store API contract-set digest" arm — a boundary that runs no store
/// makes no Store API claim at all. The binding is therefore scoped by the SAME
/// key the ORS lookup in [`OrsGenerationCoordinator::admit_generation_rollback`]
/// uses, which is the committed cutover record's `route_scope`, and it matches
/// the crate's one `STORE_BRIDGE_ROUTE` spelling rather than a second literal.
/// Every other route returns `None` and is compared byte for byte as before.
///
/// The bound operand is [`eliot_kernel_service::kernel_store_api_contract_set_digest`]:
/// the digest of the operation-manifest catalogue generated by the
/// `eliot_store_api` compiled into THIS receiver. Its counterpart is the digest
/// the store PROCESS presented, which the store-bridge seam stored on the
/// recorded evidence; neither value is taken from the other, and neither is taken
/// from the record being compared.
///
/// A receiver that cannot derive its own catalogue digest is refused here rather
/// than compared with nothing, on the same `envelope_version` refusal the
/// store-bridge seam uses for a build that cannot compute its own value.
fn store_bridge_durable_compatibility_state(
    route_scope: &str,
    durable: &DurableCompatibilityState,
) -> Result<Option<DurableCompatibilityState>, CompatibilityMismatch> {
    if route_scope != crate::STORE_BRIDGE_ROUTE {
        return Ok(None);
    }
    let receiver_held =
        eliot_kernel_service::kernel_store_api_contract_set_digest().map_err(|error| {
            CompatibilityMismatch::new(
                eliot_kernel_core::MismatchField::EnvelopeVersion,
                format!(
                    "this receiver cannot derive its own Store API contract-set digest: {error}"
                ),
            )
        })?;
    durable
        .clone()
        .with_store_api_contract_set_digest(receiver_held)
        .map(Some)
        .map_err(|error| {
            CompatibilityMismatch::new(
                eliot_kernel_core::MismatchField::EnvelopeVersion,
                format!("this receiver's own Store API contract-set digest is unusable: {error}"),
            )
        })
}

impl OrsGenerationCoordinator {
    pub(crate) fn new(ors: Arc<RedbRecoveryStore>) -> Self {
        Self {
            ors,
            cutover_routes: CutoverRouteTable::new(),
        }
    }

    /// Re-verifies one retained generation's recorded I1.12 evidence against the
    /// CURRENT durable compatibility state before that generation may be used as
    /// a rollback target (I1.12, issue #1890 W4/A2).
    ///
    /// This is the production caller of [`admit_rollback`]. "Last known good"
    /// means verified compatible with current durable formats and Authority
    /// Epoch lineage, not "it launched once": the verdict persisted with the
    /// candidate generation is re-read from ORS, projected back into the
    /// handshake evidence shape, and compared against the durable state the
    /// Kernel is running under right now.
    ///
    /// A previously launched artifact is therefore refused as a rollback target
    /// after a format, contract, architecture, seal, migration-class or
    /// epoch-lineage change, even though its own recorded verdict was admitted
    /// when it first ran.
    ///
    /// `module_id` is the route key the lookup above reads by — the committed
    /// cutover record's `route_scope` — so it is also what scopes the one
    /// receiver-held operand this path has. For the store-bridge route the
    /// comparison additionally runs against this receiver's own compiled Store
    /// API catalogue digest ([`store_bridge_durable_compatibility_state`]), which
    /// is what stops a rollback from inheriting the one-time live comparison the
    /// store-bridge seam made. For every other route scope nothing is added and
    /// the comparison is the one this method always made.
    ///
    /// # Errors
    ///
    /// Returns the exact [`CompatibilityMismatch`] produced by
    /// [`admit_rollback`], or one naming an absent/unreadable record or a
    /// receiver that cannot derive its own Store API contract-set digest, so the
    /// caller retains the field label and reason as the structured cause.
    pub(crate) fn admit_generation_rollback(
        &self,
        module_id: &str,
        generation: u64,
        durable: &DurableCompatibilityState,
    ) -> Result<(), CompatibilityMismatch> {
        let recorded = self
            .ors
            .load_versioned_artifact_registry(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| {
                CompatibilityMismatch::new(
                    eliot_kernel_core::MismatchField::EnvelopeVersion,
                    format!("generation registry is unreadable: {error}"),
                )
            })?
            .compatibility(module_id, generation)
            .cloned()
            .ok_or_else(|| {
                CompatibilityMismatch::new(
                    eliot_kernel_core::MismatchField::EnvelopeVersion,
                    "no recorded compatibility verdict exists for this generation",
                )
            })?;
        let evidence = restore_recorded_evidence(&recorded)?;
        // The same route key the lookup above resolved the record by decides
        // whether this receiver holds a Store API contract-set digest of its own,
        // so the scoping cannot drift onto a different route than the one being
        // re-verified.
        let scoped = store_bridge_durable_compatibility_state(module_id, durable)?;
        admit_rollback(&evidence, scoped.as_ref().unwrap_or(durable))
    }

    /// Restores the committed I14.14 ownership projection before the Kernel
    /// can accept work. Staged candidates are fenced first, and only the
    /// durable committed rows are allowed into the immutable route snapshot.
    /// No route identity is inferred here: the snapshot retains each
    /// record's canonical ORS route-scope hash for a later typed admission
    /// boundary.
    pub(crate) fn recover_cutover_ownership(&self) -> Result<(), String> {
        observe_recovery("kernel.recovery.cutover_ownership_requested", "attempt");
        let outcome = (|| {
            if let Err(error) = self
                .ors
                .reconcile_staged_cutover_ownership(eliot_ors::MAX_RECOVERY_PAGE)
            {
                if is_absent_cutover_ownership_table(&error) {
                    observe_recovery("kernel.recovery.cutover_ownership_absent", "empty");
                    return Ok(());
                }
                return Err(error.to_string());
            }
            observe_recovery("kernel.recovery.cutover_ownership_reconciled", "success");
            let committed = self
                .ors
                .latest_committed_cutover_ownership(eliot_ors::MAX_RECOVERY_PAGE)
                .map_err(|error| error.to_string())?;
            let snapshot =
                CutoverRouteSnapshot::rebuild(&committed).map_err(|error| error.to_string())?;
            self.cutover_routes.swap_committed(snapshot);
            observe_recovery("kernel.recovery.cutover_ownership_restored", "success");
            Ok(())
        })();
        if outcome.is_err() {
            observe_recovery("kernel.recovery.cutover_ownership_failed", "rejected");
        }
        outcome
    }

    pub(crate) fn recover(
        &self,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
    ) -> Result<(), String> {
        observe_recovery("kernel.recovery.recover_requested", "attempt");
        let outcome = self.recover_inner(generations, service, policy);
        if outcome.is_ok() {
            observe_recovery("kernel.recovery.recover_completed", "success");
        } else {
            observe_recovery("kernel.recovery.recover_failed", "rejected");
        }
        outcome
    }

    fn recover_inner(
        &self,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
    ) -> Result<(), String> {
        let _ = self
            .ors
            .reconcile_staged_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| error.to_string())?;
        observe_recovery("kernel.recovery.cutovers_reconciled", "success");
        let snapshots = self
            .ors
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| error.to_string())?;
        observe_recovery("kernel.recovery.cutovers_loaded", "success");
        if snapshots.is_empty() {
            observe_recovery("kernel.recovery.load_empty", "empty");
            return Ok(());
        }
        // Current bindings are rebuilt from verified records, and the current
        // tuple is the complete `(lineage_id, sequence)` of the most recently
        // committed cutover in durable ORS order. A bare `max()` over sequences
        // is undefined as soon as more than one lineage exists, and re-deriving
        // that number on the service's own lineage would silently attach
        // today's lineage to a record that never carried one. A row written
        // before the typed migration no longer decodes, so it cannot reach here
        // at all: a historical valid tuple never reactivates current authority.
        let current = snapshots
            .iter()
            .max_by_key(|snapshot| snapshot.operation_order())
            .map(|snapshot| snapshot.record().new_epoch.clone())
            .ok_or_else(|| "committed cutover projection was empty".to_owned())?;
        for snapshot in &snapshots {
            if snapshot.record().state != GenerationCutoverState::Committed {
                return Err("ORS route projection has invalid committed epochs".to_owned());
            }
        }
        observe_recovery("kernel.recovery.cutovers_validated", "success");
        // The service keeps its own Host-approved lineage and refuses a
        // cross-lineage or regressing target, so a record from a superseded
        // lineage fails closed here instead of being adopted.
        service
            .synchronize_authority_epoch(current)
            .map_err(|error| error.to_string())?;
        let active_epoch = service.authority_epoch();
        let mut recovered = GenerationRouter::at_epoch(active_epoch.clone());
        // I1.12 (issue #1890 W4/A2): a restart rebuilds the route table from the
        // committed cutover records, which is the one place a retained
        // generation is re-selected as a live route after it previously ran.
        // That re-selection is a rollback, so it is gated here: each restored
        // route's recorded I1.12 evidence must still validate against the
        // durable compatibility state the Kernel is running under NOW. A
        // generation that was admitted once is not thereby a valid rollback
        // target after a format, contract, architecture, seal, migration-class
        // or epoch-lineage change.
        //
        // This state is the one every route shares; the receiver-held Store API
        // contract-set digest is NOT bound here, because it belongs to the store
        // bridge alone. `admit_generation_rollback` below adds it for that one
        // route scope, from the same `route_scope` this loop reads.
        let durable = current_durable_compatibility_state(service)?;
        for snapshot in &snapshots {
            let record = snapshot.record();
            // A committed record for any other tuple — a pre-restore tuple, a
            // superseded sequence, or a tuple from a lineage that is no longer
            // active — belongs to epoch history only. Adopting it would replay
            // history into the current binding, so it stays historical and
            // never becomes the active route.
            if record.state != GenerationCutoverState::Committed
                || !record.new_epoch.is_same_authority(&active_epoch)
            {
                continue;
            }
            // The cutover record names its generation as the typed
            // `ResourceGeneration`; the ORS versioned-artifact registry keys
            // the recorded verdict by the same generation value, so the
            // rollback lookup uses that value rather than a re-derived one.
            //
            // The KEY half of that pair is this record's own `route_scope`, and
            // the ORS lookup is a strict `(module_id, generation)` pair with no
            // fallback: `compatibility_gate::persist_generation_compatibility`
            // must therefore be called with the same route scope this loop
            // passes here, never with a module id or artifact identity from the
            // same generation. The `rollback_compatibility_tests` module below
            // proves that round trip through a real ORS, including the refusal
            // a divergent key produces.
            let generation = record.new_generation.value();
            self.admit_generation_rollback(&record.route_scope, generation, &durable)
                .map_err(|mismatch| {
                    format!(
                        "restored route {} generation {} is not a valid rollback target: {} ({})",
                        record.route_scope,
                        generation,
                        mismatch.field(),
                        mismatch.reason()
                    )
                })?;
            let scope =
                RouteScope::new(record.route_scope.clone()).map_err(|error| error.to_string())?;
            let route = GenerationRoute::new(scope, record.new_generation, active_epoch.clone())
                .map_err(|error| error.to_string())?;
            recovered
                .register(route)
                .map_err(|error| error.to_string())?;
        }
        update_handshake_policy(policy, &recovered)?;
        *generations = recovered;
        observe_recovery("kernel.recovery.routes_applied", "success");
        Ok(())
    }

    pub(crate) fn persist_and_publish(
        &self,
        decision: &CutoverDecision,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
    ) -> PersistAndPublishResult {
        let mut observations = PersistAndPublishObservations::default();
        let result = self.persist_and_publish_inner(
            decision,
            generations,
            service,
            policy,
            &mut observations,
        );
        PersistAndPublishResult {
            result,
            observations,
        }
    }

    fn persist_and_publish_inner(
        &self,
        decision: &CutoverDecision,
        generations: &mut GenerationRouter,
        service: &mut KernelService,
        policy: &mut ServerHandshakePolicy,
        observations: &mut PersistAndPublishObservations,
    ) -> Result<(), String> {
        let mut candidate = generations.clone();
        candidate
            .cutover(decision)
            .map_err(|error| error.to_string())?;
        let staged = RuntimeGenerationCutoverRecord {
            cutover_id: decision.cutover_id().to_owned(),
            route_scope: decision.route_scope().as_str().to_owned(),
            old_generation: decision.old_generation(),
            new_generation: decision.new_generation(),
            // The durable ORS record carries the complete typed tuples, so a
            // reader can no longer lose the lineage. Nothing here narrows an
            // `EpochId` to a sequence: the record written here is the same
            // tuple the router advanced on, and every authorization decision
            // still reads the live route table.
            old_epoch: decision.old_epoch().clone(),
            new_epoch: decision.new_epoch().clone(),
            state: GenerationCutoverState::Armed,
        };
        self.ors
            .stage_generation_cutover(staged.clone())
            .map_err(|error| error.to_string())?;
        observations.cutover_staged = true;
        let committed = self
            .ors
            .commit_generation_cutover_state(staged)
            .map_err(|error| error.to_string())?;
        if committed.record().state != GenerationCutoverState::Committed {
            return Err("ORS did not return a committed cutover".to_owned());
        }
        observations.cutover_committed = true;
        // Same exact-tuple bridge as `recover`: the durable record projected the
        // canonical decision sequence; the service is then synchronized on the
        // complete tuple, which fails closed on a cross-lineage target or a
        // regression. The decision itself is never widened by its sequence.
        let decision_canonical = decision.new_epoch().clone();
        service
            .synchronize_authority_epoch(decision_canonical)
            .map_err(|error| error.to_string())?;
        observations.handshake_policy = Some(update_handshake_policy_without_observation(
            policy, &candidate,
        )?);
        *generations = candidate;
        observations.cutover_applied = true;
        Ok(())
    }
}

/// Older ORS databases predate the optional I14.14 ownership table. An absent
/// table means there are no committed cutover rows to restore; it is distinct
/// from a present table whose contents fail validation and must remain
/// terminal. The ORS crate currently exposes the redb absence only through
/// its typed storage message, so keep this compatibility test local to the
/// Kernel recovery boundary.
fn is_absent_cutover_ownership_table(error: &OrsError) -> bool {
    matches!(
        error,
        OrsError::Storage(message)
            if message.contains("Table 'ors_cutover_ownership_v1' does not exist")
    )
}

pub(crate) fn update_handshake_policy(
    policy: &mut ServerHandshakePolicy,
    generations: &GenerationRouter,
) -> Result<(), String> {
    let observation = update_handshake_policy_without_observation(policy, generations)?;
    observation.emit();
    Ok(())
}

fn update_handshake_policy_without_observation(
    policy: &mut ServerHandshakePolicy,
    generations: &GenerationRouter,
) -> Result<HandshakePolicyObservation, String> {
    let daemon = RouteScope::new("daemon").map_err(|error| error.to_string())?;
    if let Ok(route) = generations.route(&daemon) {
        let artifact_digest = policy.config_snapshot.get("artifact_digest").cloned();
        let protected_snapshot_digest = policy
            .config_snapshot
            .get("protected_snapshot_digest")
            .cloned();
        if let Some(protected_snapshot_digest) = protected_snapshot_digest.as_ref() {
            let Some(value) = protected_snapshot_digest.as_str() else {
                return Err("Kernel protected snapshot digest must be a JSON string".to_owned());
            };
            if !is_lower_sha256(value) {
                return Err("Kernel protected snapshot digest must be lowercase SHA-256".to_owned());
            }
        }
        policy.module_generation.generation = route.active_generation();
        // Exact tuple equality (Implements #64): the policy fence adopts the
        // route's complete `EpochId`. Re-deriving a sequence on the policy's
        // own lineage is what previously let a route from another lineage be
        // rewritten into the current one, so a lineage disagreement is now a
        // terminal policy error instead of a silent rewrite.
        if policy
            .module_generation
            .state_fence
            .authority_epoch
            .lineage_id
            != route.authority_epoch().lineage_id
        {
            return Err(
                "Kernel handshake policy epoch lineage disagrees with the route".to_owned(),
            );
        }
        policy.module_generation.state_fence =
            StateFence::new(route.authority_epoch().clone(), route.active_generation());
        policy.config_snapshot = serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "generation": route.active_generation().value(),
            "authority_epoch": route.authority_epoch(),
        });
        if let Some(artifact_digest) = artifact_digest {
            policy.config_snapshot["artifact_digest"] = artifact_digest;
        }
        if let Some(protected_snapshot_digest) = protected_snapshot_digest {
            policy.config_snapshot["protected_snapshot_digest"] = protected_snapshot_digest;
        }
        Ok(HandshakePolicyObservation::Projected)
    } else {
        Ok(HandshakePolicyObservation::Absent)
    }
}

#[cfg(test)]
mod generation_recovery_diagnostics_tests {
    //! F-LOG-KERNEL-4 (#903 slice B) focused diagnostics proof: the
    //! handshake-projection boundary keeps its exact owner behavior while
    //! recording only fixed, secret-free observation names.

    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::{KernelComposition, KernelConfig, unix_ms};
    use eliot_contracts::AuthorityEpoch;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn test_epoch(sequence: u64) -> eliot_contracts::EpochId {
        eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("test lineage"),
            std::num::NonZeroU64::new(sequence).expect("test sequence"),
        )
        .expect("test epoch")
    }

    fn capture(run: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer_sink.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run);
        }
        String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned()
    }

    #[test]
    fn startup_restores_committed_cutover_routes_only() {
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-cutover-recovery-{}-{}.redb",
            std::process::id(),
            unix_ms()
        ));
        let _ = std::fs::remove_file(&path);
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));
        let scope =
            eliot_ors::CapabilityRouteScope::declare("mod-startup", "serve", "work", "effects")
                .expect("route scope");
        let route_scope_hash = scope.route_scope_hash.clone();
        let record = eliot_ors::GenerationCutoverOwnership {
            cutover_id: "cutover-startup-recovery".to_owned(),
            candidate_artifact: eliot_ors::ModuleArtifactIdentity {
                module_id: "mod-startup".to_owned(),
                semver: "1.0.0".to_owned(),
                artifact_hash: "a".repeat(64),
                manifest_digest: "b".repeat(64),
                layout_root: format!("modules/mod-startup/1.0.0/{}", "a".repeat(64)),
            },
            incumbent_artifact: None,
            scope,
            old_generation: None,
            new_generation: eliot_contracts::ResourceGeneration::new(2).expect("generation"),
            old_epoch: AuthorityEpoch::new(1).expect("epoch"),
            new_epoch: AuthorityEpoch::new(2).expect("epoch"),
            in_flight: Vec::new(),
            migration: eliot_ors::StateMigrationDecision::RetainCompatible,
            health_proof_ref: "health-proof-startup".to_owned(),
            rollback_boundary: "forward-only".to_owned(),
            unresolved_scopes: Vec::new(),
            linearization_record_id: None,
            state: GenerationCutoverState::Armed,
        };
        store
            .stage_cutover_ownership(record)
            .expect("stage cutover ownership");
        store
            .commit_cutover_ownership("cutover-startup-recovery")
            .expect("commit cutover ownership");

        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));
        coordinator
            .recover_cutover_ownership()
            .expect("restore committed cutover ownership");
        assert_eq!(
            coordinator.cutover_routes.admit(
                &route_scope_hash,
                eliot_contracts::ResourceGeneration::new(2).expect("generation"),
                AuthorityEpoch::new(2).expect("epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::AdmitCandidate
        );
        assert_eq!(
            coordinator.cutover_routes.admit(
                "unrecorded-route-scope",
                eliot_contracts::ResourceGeneration::new(2).expect("generation"),
                AuthorityEpoch::new(2).expect("epoch"),
                "new-operation",
            ),
            eliot_ors::CutoverAdmission::RejectStale
        );

        drop(coordinator);
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn recovery_handshake_observation_preserves_policy_projection() {
        // A real composition supplies the policy contour and a real router
        // supplies the daemon route. Both legs run through the existing
        // `update_handshake_policy` caller — never a copied projection.
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-recovery-diagnostics-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
        let baseline = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy lock")
            .clone();

        // Projected leg: the daemon route drives generation, fence epoch,
        // and snapshot exactly as before; only fixed names reach the sink.
        let epoch = test_epoch(7);
        let mut router = GenerationRouter::at_epoch(epoch.clone());
        let scope = RouteScope::new("daemon").expect("daemon scope");
        let generation = eliot_contracts::ResourceGeneration::new(3).expect("generation");
        router
            .register(GenerationRoute::new(scope, generation, epoch.clone()).expect("route"))
            .expect("register");
        let mut policy = baseline.clone();
        policy.config_snapshot["artifact_digest"] =
            serde_json::Value::String("artifact-canary-string".to_owned());
        policy.config_snapshot["protected_snapshot_digest"] =
            serde_json::Value::String("e".repeat(64));
        let text = capture(|| {
            update_handshake_policy(&mut policy, &router).expect("policy update");
        });
        assert!(
            text.contains("kernel.recovery.handshake_projected"),
            "missing diagnostics marker kernel.recovery.handshake_projected"
        );
        assert!(
            !text.contains("artifact-canary-string"),
            "policy material leaked into diagnostics"
        );
        assert_eq!(policy.module_generation.generation.value(), 3);
        let fence = &policy.module_generation.state_fence;
        assert_eq!(fence.authority_epoch.sequence.get(), 7);
        assert_eq!(fence.resource_generation.value(), 3);
        assert_eq!(
            policy.config_snapshot["generation"],
            serde_json::json!(3u64)
        );
        assert_eq!(
            policy.config_snapshot["authority_epoch"],
            serde_json::to_value(&epoch).expect("epoch json")
        );
        assert_eq!(
            policy.config_snapshot["service"],
            serde_json::json!(SERVICE_NAME)
        );
        assert_eq!(
            policy.config_snapshot["protocol"],
            serde_json::json!(PROTOCOL_VERSION)
        );
        assert_eq!(
            policy.config_snapshot["artifact_digest"],
            serde_json::json!("artifact-canary-string")
        );
        assert_eq!(
            policy.config_snapshot["protected_snapshot_digest"],
            serde_json::json!("e".repeat(64))
        );

        // Absent leg: without a daemon route the policy is byte-identical
        // and the omission — not a projection — is recorded.
        let empty = GenerationRouter::at_epoch(epoch);
        let mut policy = baseline.clone();
        let before = policy.clone();
        let text = capture(|| {
            update_handshake_policy(&mut policy, &empty).expect("absent policy update");
        });
        assert!(
            text.contains("kernel.recovery.handshake_absent"),
            "missing diagnostics marker kernel.recovery.handshake_absent"
        );
        assert_eq!(policy, before);

        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod rollback_compatibility_tests {
    //! #1968 round-trip proof: the verdict a Kernel process boundary records is
    //! only reachable by the restart rollback gate when both sides agree on the
    //! `(module_id, generation)` key.
    //!
    //! `VersionedArtifactRegistry::compatibility` builds that key from the
    //! module-id string it is handed and falls back to nothing, and
    //! `admit_generation_rollback` hands it a committed cutover record's
    //! `route_scope`. These proofs therefore run a real `RedbRecoveryStore`
    //! through the production producers (`compatibility_gate`'s durable state
    //! and admission) and the production persist call, then re-read the row
    //! through the gate itself. Nothing is hand-built: no envelope is
    //! constructed here, no stored row is edited, and no digest is recomputed.

    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::OrsGenerationCoordinator;
    use crate::frame_dispatch::RUNTIME_HEALTH_ROUTE_SCOPE;
    use crate::{KernelComposition, KernelConfig, unix_ms};
    use eliot_contracts::{EpochId, ResourceGeneration};
    use eliot_kernel_core::{DurableCompatibilityState, MismatchField, VersionRange};
    use eliot_ors::RedbRecoveryStore;
    use std::path::PathBuf;
    use std::sync::Arc;

    /// One real composition in a unique directory under the OS temp directory.
    ///
    /// Its live service Authority Epoch is the durable state a restored route
    /// is compared against, and its front-door policy is this composition's own
    /// module identity; both are read from the built composition rather than
    /// restated here.
    pub(super) fn proof_composition(label: &str) -> (KernelComposition, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-rollback-key-{label}-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
        (kernel, root)
    }

    /// A fresh ORS database path per proof. Never a fixed name, never outside
    /// the OS temp directory, so no two runs share a durable row family.
    pub(super) fn unique_ors_path(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "eliot-kernel-rollback-verdict-{label}-{}-{}.redb",
            std::process::id(),
            unix_ms()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// Admits one generation against the durable state the Kernel runs under and
    /// records that admission under `key`, exactly as the daemon and store
    /// bridge boundaries do. Returns the durable state the verdict was admitted
    /// against, which the rollback gate must be handed unchanged to admit it.
    pub(super) fn record_admitted_verdict(
        store: &RedbRecoveryStore,
        key: &str,
        generation: ResourceGeneration,
        authority_epoch: &EpochId,
    ) -> DurableCompatibilityState {
        let durable = crate::compatibility_gate::durable_compatibility_state(authority_epoch)
            .expect("durable compatibility state");
        let activation = crate::compatibility_gate::admit_generation_activation(
            generation,
            authority_epoch,
            i64::try_from(unix_ms()).expect("observation clock"),
        )
        .expect("candidate admitted against its own durable state");
        assert!(
            activation.refusal().is_none(),
            "the recorded verdict must be an admitted one"
        );
        crate::compatibility_gate::persist_generation_compatibility(
            store,
            key,
            &"a".repeat(64),
            &activation,
        )
        .expect("persist the admitted verdict");
        durable
    }

    /// The same durable state with only its canonical format range replaced,
    /// produced by the owner crate's real `DurableCompatibilityState` producer
    /// from the state that admitted the generation. No stored row is edited to
    /// make the rollback gate refuse anything.
    fn durable_state_with_canonical_format_range(
        durable: &DurableCompatibilityState,
        canonical_format_range: VersionRange,
        authority_epoch: &EpochId,
    ) -> DurableCompatibilityState {
        DurableCompatibilityState::new(
            durable.protocol_range(),
            durable.contract_set_digest(),
            canonical_format_range,
            durable.architecture_source_digest(),
            authority_epoch.clone(),
            durable.required_capabilities().to_vec(),
            durable.migration_class(),
        )
        .expect("durable compatibility state")
    }

    /// A verdict recorded under the route scope the rollback gate looks it up by
    /// is admitted again after a restart, and the recorded row carries the
    /// generation and the epoch lineage it was admitted with.
    #[test]
    fn recorded_generation_verdict_is_admitted_under_the_route_scope_key() {
        let (kernel, root) = proof_composition("round-trip");
        let authority_epoch = kernel
            .service
            .lock()
            .expect("service lock")
            .authority_epoch();
        let front_door_module_id = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy lock")
            .module_id
            .clone();
        assert_ne!(
            front_door_module_id, RUNTIME_HEALTH_ROUTE_SCOPE,
            "the module-id namespace and the route-scope key must be different keys"
        );

        let path = unique_ors_path("round-trip");
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));
        let generation = ResourceGeneration::new(7).expect("generation");
        let durable = record_admitted_verdict(
            &store,
            RUNTIME_HEALTH_ROUTE_SCOPE,
            generation,
            &authority_epoch,
        );
        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));

        coordinator
            .admit_generation_rollback(RUNTIME_HEALTH_ROUTE_SCOPE, generation.value(), &durable)
            .expect("the recorded verdict admits its own generation under the route-scope key");

        let registry = store
            .load_versioned_artifact_registry(eliot_ors::MAX_RECOVERY_PAGE)
            .expect("versioned artifact registry");
        let recorded = registry
            .compatibility(RUNTIME_HEALTH_ROUTE_SCOPE, generation.value())
            .expect("recorded verdict under the route-scope key");
        recorded
            .require()
            .expect("the recorded verdict is an admitted one");
        assert_eq!(recorded.module_generation(), generation.value());
        assert_eq!(
            recorded.authority_lineage_id(),
            authority_epoch.lineage_id.to_string()
        );
        assert_eq!(
            recorded.authority_sequence(),
            authority_epoch.sequence.get()
        );

        // Positive control for the defect this issue measured: the SAME durable
        // state and the SAME generation under the module-id namespace the
        // boundary used to persist by resolve nothing, because the registry key
        // is strict and has no fallback. Re-introducing that mismatch fails the
        // assertions here rather than in production.
        assert!(
            registry
                .compatibility(front_door_module_id.as_str(), generation.value())
                .is_none()
        );
        let mismatch = coordinator
            .admit_generation_rollback(front_door_module_id.as_str(), generation.value(), &durable)
            .expect_err("the module-id namespace must not resolve the route-scope verdict");
        assert_eq!(mismatch.field(), MismatchField::EnvelopeVersion);
        assert_eq!(
            mismatch.reason(),
            "no recorded compatibility verdict exists for this generation"
        );

        drop(coordinator);
        drop(store);
        drop(kernel);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(root);
    }

    /// "Previously launched" is not a valid rollback target: once the durable
    /// canonical-format range has moved past what the recorded verdict was
    /// negotiated on, the gate refuses that generation with the mismatching
    /// field instead of replaying the admission it once received.
    #[test]
    fn recorded_generation_verdict_is_refused_after_durable_format_drift() {
        let (kernel, root) = proof_composition("format-drift");
        let authority_epoch = kernel
            .service
            .lock()
            .expect("service lock")
            .authority_epoch();
        let path = unique_ors_path("format-drift");
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));
        let generation = ResourceGeneration::new(9).expect("generation");
        let durable = record_admitted_verdict(
            &store,
            RUNTIME_HEALTH_ROUTE_SCOPE,
            generation,
            &authority_epoch,
        );
        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));
        coordinator
            .admit_generation_rollback(RUNTIME_HEALTH_ROUTE_SCOPE, generation.value(), &durable)
            .expect("admitted while the durable state still matches the verdict");

        let registry = store
            .load_versioned_artifact_registry(eliot_ors::MAX_RECOVERY_PAGE)
            .expect("versioned artifact registry");
        let recorded = registry
            .compatibility(RUNTIME_HEALTH_ROUTE_SCOPE, generation.value())
            .expect("recorded verdict");
        let admitted_format_version = recorded
            .admitted_canonical_format_version()
            .expect("negotiated canonical format version");
        let drifted = durable_state_with_canonical_format_range(
            &durable,
            VersionRange::new(admitted_format_version + 1, admitted_format_version + 1)
                .expect("drifted canonical format range"),
            &authority_epoch,
        );
        let mismatch = coordinator
            .admit_generation_rollback(RUNTIME_HEALTH_ROUTE_SCOPE, generation.value(), &drifted)
            .expect_err("a drifted durable format range is not a rollback target");
        assert_eq!(mismatch.field(), MismatchField::CanonicalFormatRange);

        drop(coordinator);
        drop(store);
        drop(kernel);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(root);
    }
}

/// #1968 store-bridge rollback proof: the receiver-held Store API contract-set
/// digest is bound on the rollback path for the store-bridge route scope alone,
/// so a store-bridge generation whose recorded catalogue IS this build's is
/// admitted again, and one whose recorded catalogue is not is refused with the
/// exact I1.12 field.
///
/// These proofs reuse the composition, ORS-path and recording helpers of
/// [`rollback_compatibility_tests`] rather than restating them, and they reach
/// the store-bridge production sequence itself: the activation gate, the
/// peer-presented `record_store_api_contract_set` binder the store-bridge seam
/// calls, and `persist_generation_compatibility` under the crate's one
/// `STORE_BRIDGE_ROUTE` spelling. No envelope is hand-built, no stored row is
/// edited, and the receiver's own value is never written into a row.
#[cfg(test)]
mod store_bridge_catalogue_rollback_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::OrsGenerationCoordinator;
    use super::rollback_compatibility_tests::{
        proof_composition, record_admitted_verdict, unique_ors_path,
    };
    use crate::frame_dispatch::RUNTIME_HEALTH_ROUTE_SCOPE;
    use crate::unix_ms;
    use eliot_contracts::{EpochId, ResourceGeneration};
    use eliot_kernel_core::{DurableCompatibilityState, MismatchField};
    use eliot_ors::RedbRecoveryStore;
    use std::sync::Arc;

    /// Records one store-bridge generation's verdict exactly as the store-bridge
    /// seam records it: the production activation gate, then the digest the STORE
    /// PROCESS presented bound onto the accepted evidence, then the production
    /// persist call keyed by the store-bridge route scope the rollback lookup
    /// reads by.
    ///
    /// `presented` is the store's operand, never the Kernel's expectation, so the
    /// row this leaves behind is the operand a later rollback re-verifies against
    /// the receiver's own compiled catalogue.
    fn record_store_bridge_verdict(
        store: &RedbRecoveryStore,
        generation: ResourceGeneration,
        authority_epoch: &EpochId,
        presented: &str,
    ) -> DurableCompatibilityState {
        let durable = crate::compatibility_gate::durable_compatibility_state(authority_epoch)
            .expect("durable compatibility state");
        let activation = crate::compatibility_gate::admit_generation_activation(
            generation,
            authority_epoch,
            i64::try_from(unix_ms()).expect("observation clock"),
        )
        .expect("the store-bridge candidate is admitted by the envelope gate");
        let activation = activation
            .record_store_api_contract_set(presented)
            .expect("the presented store catalogue is recorded on the admitted verdict");
        crate::compatibility_gate::persist_generation_compatibility(
            store,
            crate::STORE_BRIDGE_ROUTE,
            &"b".repeat(64),
            &activation,
        )
        .expect("persist the store-bridge verdict");
        durable
    }

    /// The digest a store binary built against a DIFFERENTLY BUILT
    /// `eliot_store_api` presents: the real whole-catalogue set digest over this
    /// build's catalogue with one named entry dropped, which is the shape a
    /// narrower or older store release generates.
    ///
    /// It goes through the store API's own `operation_manifest_set_digest`, and it
    /// never reads `kernel_store_api_contract_set_digest`, so a refusal produced
    /// from it is a disagreement between two builds and cannot be reached by the
    /// receiver echoing its own value.
    fn differently_built_store_digest() -> String {
        let mut entries =
            eliot_store_api::generated_operation_manifests().expect("this build's catalogue");
        entries
            .pop()
            .expect("the catalogue ends with its genesis entry");
        eliot_store_api::operation_manifest_set_digest(&entries)
            .expect("the narrower catalogue's set digest computes")
            .as_str()
            .to_owned()
    }

    /// The digest this Kernel holds, produced by its own producer. No literal
    /// digest is used anywhere in this module, so a proof here cannot pass by
    /// comparing a fixture with itself.
    fn receiver_held_digest() -> String {
        eliot_kernel_service::kernel_store_api_contract_set_digest()
            .expect("this build's Store API contract-set digest computes")
    }

    /// The live service Authority Epoch of a real composition, which is the epoch
    /// every durable state below is built from.
    fn live_authority_epoch(kernel: &crate::KernelComposition) -> EpochId {
        kernel
            .service
            .lock()
            .expect("service lock")
            .authority_epoch()
    }

    /// The point of the change: a store-bridge generation whose recorded
    /// catalogue digest is the one THIS build's own compiled `eliot_store_api`
    /// produces is a valid rollback target again.
    ///
    /// Before the receiver-held side was bound on this path, the same row was
    /// refused on the "this receiver holds no Store API contract-set digest of its
    /// own" arm, because the receiver held none and the record held one.
    #[test]
    fn store_bridge_generation_is_admitted_when_the_recorded_catalogue_is_this_builds_own() {
        let (kernel, root) = proof_composition("store-bridge-admit");
        let authority_epoch = live_authority_epoch(&kernel);
        let path = unique_ors_path("store-bridge-admit");
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));
        let generation = ResourceGeneration::new(11).expect("generation");
        // What a store built against this same `eliot_store_api` presents: the
        // Kernel's own producer, so the agreement under test is between the
        // recorded peer operand and the receiver's compiled catalogue.
        let presented = receiver_held_digest();
        let durable = record_store_bridge_verdict(&store, generation, &authority_epoch, &presented);

        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));
        coordinator
            .admit_generation_rollback(crate::STORE_BRIDGE_ROUTE, generation.value(), &durable)
            .expect("a store-bridge generation recorded against this build's catalogue admits");

        // The row really does carry the peer operand, so the admission above came
        // through the store-catalogue comparison rather than around it.
        let registry = store
            .load_versioned_artifact_registry(eliot_ors::MAX_RECOVERY_PAGE)
            .expect("versioned artifact registry");
        assert_eq!(
            registry
                .compatibility(crate::STORE_BRIDGE_ROUTE, generation.value())
                .expect("the recorded store-bridge verdict")
                .store_api_contract_set_digest(),
            Some(presented.as_str())
        );

        drop(coordinator);
        drop(store);
        drop(kernel);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(root);
    }

    /// The other direction, with the mismatch produced by choosing what a STORE
    /// presents. A store binary compiled against a different `eliot_store_api`
    /// was admitted by the live seam once; it is not a rollback target now.
    #[test]
    fn store_bridge_generation_is_refused_when_the_recorded_catalogue_differs() {
        let (kernel, root) = proof_composition("store-bridge-refuse");
        let authority_epoch = live_authority_epoch(&kernel);
        let path = unique_ors_path("store-bridge-refuse");
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));
        let generation = ResourceGeneration::new(12).expect("generation");
        let presented = differently_built_store_digest();
        assert_ne!(
            presented,
            receiver_held_digest(),
            "the store operand must be a different catalogue, not the receiver's own"
        );
        let durable = record_store_bridge_verdict(&store, generation, &authority_epoch, &presented);

        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));
        let mismatch = coordinator
            .admit_generation_rollback(crate::STORE_BRIDGE_ROUTE, generation.value(), &durable)
            .expect_err("a differently built store is not a valid rollback target");
        assert_eq!(mismatch.field(), MismatchField::StoreApiContractSet);

        drop(coordinator);
        drop(store);
        drop(kernel);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(root);
    }

    /// The scoping did not over-refuse. A route that runs no store records no
    /// Store API claim, and it keeps being admitted: binding the receiver-held
    /// digest for this route would refuse it on the "recorded evidence carries no
    /// Store API contract-set digest" arm.
    #[test]
    fn non_store_bridge_route_without_a_recorded_catalogue_is_still_admitted() {
        let (kernel, root) = proof_composition("scoping");
        let authority_epoch = live_authority_epoch(&kernel);
        let path = unique_ors_path("scoping");
        let store = Arc::new(RedbRecoveryStore::open(&path).expect("open ORS"));
        let generation = ResourceGeneration::new(13).expect("generation");
        // The daemon boundary's recording path: an admitted verdict with no Store
        // API digest bound onto it at all.
        let durable = record_admitted_verdict(
            &store,
            RUNTIME_HEALTH_ROUTE_SCOPE,
            generation,
            &authority_epoch,
        );
        let coordinator = OrsGenerationCoordinator::new(Arc::clone(&store));
        coordinator
            .admit_generation_rollback(RUNTIME_HEALTH_ROUTE_SCOPE, generation.value(), &durable)
            .expect("a non-store route records no Store API claim and is admitted as before");

        drop(coordinator);
        drop(store);
        drop(kernel);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(root);
    }

    /// The receiver-held operand is the digest of THIS build's own compiled
    /// `eliot_store_api`, and it is bound for the store-bridge route scope alone.
    ///
    /// The comparison's other operand is the value the store PROCESS presented,
    /// stored on the recorded evidence; nothing here derives it from the receiver.
    #[test]
    fn receiver_held_digest_is_bound_only_for_the_store_bridge_route_scope() {
        let (kernel, root) = proof_composition("receiver-scope");
        let authority_epoch = live_authority_epoch(&kernel);
        let durable = crate::compatibility_gate::durable_compatibility_state(&authority_epoch)
            .expect("durable compatibility state");
        assert_eq!(
            durable.store_api_contract_set_digest(),
            None,
            "the shared durable state holds no Store API digest"
        );

        let scoped =
            super::store_bridge_durable_compatibility_state(crate::STORE_BRIDGE_ROUTE, &durable)
                .expect("the store bridge's receiver side derives")
                .expect("the store-bridge route holds a receiver-held digest");
        assert_eq!(
            scoped.store_api_contract_set_digest(),
            Some(receiver_held_digest().as_str())
        );
        // The same value the store API's own whole-catalogue digest produces, so
        // this is the catalogue and not a single entry or a fixture.
        assert_eq!(
            scoped.store_api_contract_set_digest(),
            Some(
                eliot_store_api::operation_manifest_set_digest(
                    &eliot_store_api::generated_operation_manifests()
                        .expect("this build's own catalogue generates")
                )
                .expect("this build's own catalogue digest computes")
                .as_str()
            )
        );

        // Every other route scope keeps today's behaviour: no receiver-held
        // digest, so nothing new can be refused on that field.
        for route_scope in [RUNTIME_HEALTH_ROUTE_SCOPE, "another_route", "store_bridge "] {
            assert!(
                super::store_bridge_durable_compatibility_state(route_scope, &durable)
                    .expect("a non-store route derives nothing")
                    .is_none(),
                "route scope {route_scope} must not receive a receiver-held Store API digest"
            );
        }

        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }
}
