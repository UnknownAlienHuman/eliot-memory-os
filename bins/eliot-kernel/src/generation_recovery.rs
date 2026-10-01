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
    GenerationRouter, RouteScope, StateMigrationClass, VersionRange, admit_rollback,
    restore_recorded_evidence,
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
/// (`frame_dispatch::runtime_compatibility_evidence`), so the rollback gate and
/// the activation handshake are compared against one durable state rather than
/// two independently derived projections. It is derived from the running
/// binary's own protocol/format/contract/architecture identity and the service's
/// current authority epoch; nothing is invented and no evidence is carried over
/// from a previous process.
fn current_durable_compatibility_state(
    service: &KernelService,
) -> Result<DurableCompatibilityState, String> {
    let protocol_range = VersionRange::new(1, 1).map_err(|error| error.to_string())?;
    let canonical_format_range = VersionRange::new(1, 1).map_err(|error| error.to_string())?;
    let contract_set_digest =
        super::frame_dispatch::runtime_contract_set_digest().map_err(|error| error.to_string())?;
    DurableCompatibilityState::new(
        protocol_range,
        contract_set_digest,
        canonical_format_range,
        eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST,
        service.authority_epoch(),
        vec![super::frame_dispatch::RUNTIME_HEALTH_CAPABILITY.to_owned()],
        StateMigrationClass::NoMigration,
    )
    .map_err(|error| error.to_string())
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
    /// # Errors
    ///
    /// Returns the exact [`CompatibilityMismatch`] produced by
    /// [`admit_rollback`], or one naming an absent/unreadable record, so the
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
        admit_rollback(&evidence, durable)
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

    /// Restores the committed I14.15 daemon-cutover fence before the Kernel can
    /// accept work (issue #1952).
    ///
    /// A `DaemonCutoverRecord` that fenced an old `eliotd` generation must still
    /// fence it after a restart: without this read the old generation's unstaged
    /// proposals would become unstale purely because the process restarted, which
    /// is exactly the race the record exists to close. Only rows the ORS commit
    /// transaction linearized are read — a staged candidate is never a fence —
    /// and the retained set is checked as one advancing lineage by the owner's own
    /// `validate_daemon_cutover_lineage`, so an incoherent stored chain fails
    /// closed here instead of being adopted as the daemon authority.
    ///
    /// The retained rows are then checked against each other, and the fence they
    /// name is READ here rather than re-derived: this pass establishes that the
    /// durable daemon-cutover chain is coherent and therefore that an unstaged
    /// old-daemon proposal is stale after a restart. It deliberately does NOT
    /// compare the record to the router's `daemon` route: I14.15 commits the
    /// record and then publishes the candidate route, and the route projection
    /// carries the global current epoch rather than this record's own, so such a
    /// comparison would refuse a correctly recorded cutover rather than catch a
    /// wrong one.
    ///
    /// Nothing is inferred: no generation, epoch, fence, or staged-operation
    /// identity is derived here, and this restores state rather than granting it.
    /// An ORS database written before the daemon table existed has no committed
    /// daemon cutover, which is the same fact as an empty set.
    pub(crate) fn recover_daemon_cutover_ownership(&self) -> Result<(), String> {
        observe_recovery("kernel.recovery.daemon_cutover_requested", "attempt");
        let outcome = (|| {
            let committed = match self
                .ors
                .latest_committed_daemon_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            {
                Ok(committed) => committed,
                Err(error) if is_absent_daemon_cutover_table(&error) => {
                    observe_recovery("kernel.recovery.daemon_cutover_absent", "empty");
                    return Ok(());
                }
                Err(error) => return Err(error.to_string()),
            };
            if committed.is_empty() {
                observe_recovery("kernel.recovery.daemon_cutover_absent", "empty");
                return Ok(());
            }
            eliot_ors::validate_daemon_cutover_lineage(&committed)
                .map_err(|error| error.to_string())?;
            observe_recovery("kernel.recovery.daemon_cutover_restored", "success");
            Ok(())
        })();
        if outcome.is_err() {
            observe_recovery("kernel.recovery.daemon_cutover_failed", "rejected");
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
        // I14.15 (issue #1952): the committed daemon-cutover chain is read back
        // here, before this recovery reports success. Placing it AFTER
        // `recover_inner` rather than inside it is deliberate: that function
        // returns early when no generation cutover exists, and a committed daemon
        // cutover must be restored on a restart regardless of that, because the
        // fence it carries is what keeps an old `eliotd` generation's unstaged
        // proposals stale across the restart.
        let outcome = self
            .recover_inner(generations, service, policy)
            .and_then(|()| self.recover_daemon_cutover_ownership());
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

/// The I14.15 daemon-cutover table is optional for the same reason as
/// `CUTOVER_OWNERSHIP`: an ORS database written before issue #1952 has no
/// committed daemon cutover, and an absent table is that same fact. It is
/// distinct from a present table whose contents fail validation, which stays
/// terminal in [`OrsGenerationCoordinator::recover_daemon_cutover_ownership`].
/// The ORS crate exposes the redb absence only through its typed storage message,
/// so keep this compatibility read local to the Kernel recovery boundary.
fn is_absent_daemon_cutover_table(error: &OrsError) -> bool {
    matches!(
        error,
        OrsError::Storage(message)
            if message.contains("Table 'ors_daemon_cutover_ownership_v1' does not exist")
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
